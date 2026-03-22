<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * Backported from PocketMine-MP 5.41.1
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\auth;

use pocketmine\network\mcpe\protocol\ProtocolInfo;
use pocketmine\scheduler\AsyncTask;
use pocketmine\thread\NonThreadSafeValue;
use pocketmine\utils\Internet;
use pocketmine\utils\InternetException;
use pocketmine\utils\InternetRequestResult;
use function gettype;
use function is_array;
use function is_object;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;

/**
 * Async task that fetches Mojang's public RSA keys used to verify OpenID tokens.
 *
 * Flow:
 *   1. Fetch discovery document from Minecraft Services (contains auth service URL)
 *   2. Fetch OpenID configuration from auth service (contains JWKS URI and issuer)
 *   3. Fetch JWKS (JSON Web Key Set) to get the actual RSA keys
 *
 * Backported from PM5.41.1 - new in Bedrock 1.26.0 authentication flow.
 */
class FetchAuthKeysTask extends AsyncTask{
	private const KEYS_ON_COMPLETION = "completion";

	/**
	 * Minecraft Services discovery endpoint. Returns JSON containing service URLs.
	 * The protocol version is embedded so Mojang can route different client versions
	 * to different auth environments.
	 */
	private const MINECRAFT_SERVICES_DISCOVERY_URL =
		"https://client.discovery.minecraft-services.net/api/v1.0/discovery/MinecraftPE/builds/" .
		ProtocolInfo::MINECRAFT_VERSION_NETWORK;

	private const AUTHORIZATION_SERVICE_URI_FALLBACK =
		"https://authorization.franchise.minecraft-services.net";

	private const AUTHORIZATION_SERVICE_OPENID_CONFIG_PATH = "/.well-known/openid-configuration";
	private const AUTHORIZATION_SERVICE_KEYS_PATH = "/.well-known/keys";

	/**
	 * @phpstan-var NonThreadSafeValue<array<string, string>>|null keys indexed by kid => DER key
	 */
	private ?NonThreadSafeValue $keys = null;

	private string $issuer = self::AUTHORIZATION_SERVICE_URI_FALLBACK;

	/**
	 * @phpstan-var NonThreadSafeValue<non-empty-array<string>>|null
	 */
	private ?NonThreadSafeValue $errors = null;

	/**
	 * @phpstan-param \Closure(?array<string, string> $keys, string $issuer, ?string[] $errors) : void $onCompletion
	 */
	public function __construct(\Closure $onCompletion){
		$this->storeLocal(self::KEYS_ON_COMPLETION, $onCompletion);
	}

	public function onRun() : void{
		/** @var string[] $errors */
		$errors = [];

		// Step 1: Get auth service URI from Minecraft Services discovery
		try{
			$authServiceUri = $this->getAuthServiceUri();
		}catch(\RuntimeException $e){
			$errors[] = "Discovery failed: " . $e->getMessage();
			$authServiceUri = self::AUTHORIZATION_SERVICE_URI_FALLBACK;
		}

		// Step 2: Get OpenID configuration (issuer + JWKS URI)
		try{
			[$jwksUri, $this->issuer] = $this->getOpenIdConfig($authServiceUri);
		}catch(\RuntimeException $e){
			$errors[] = "OpenID config fetch failed: " . $e->getMessage();
			$jwksUri = $authServiceUri . self::AUTHORIZATION_SERVICE_KEYS_PATH;
			$this->issuer = $authServiceUri;
		}

		// Step 3: Fetch keys from JWKS URI
		try{
			$this->keys = new NonThreadSafeValue($this->fetchDerKeys($jwksUri));
		}catch(\RuntimeException $e){
			$errors[] = "JWKS fetch failed: " . $e->getMessage();
		}

		$this->errors = $errors === [] ? null : new NonThreadSafeValue($errors);
	}

	/**
	 * @throws \RuntimeException
	 */
	private static function fetchJson(string $url) : mixed{
		try{
			$result = Internet::simpleCurl($url, timeout: 10);
			if($result->getCode() !== 200){
				throw new \RuntimeException("Unexpected HTTP " . $result->getCode() . " from $url");
			}
			return json_decode($result->getBody(), false, flags: JSON_THROW_ON_ERROR);
		}catch(InternetException $e){
			throw new \RuntimeException("HTTP request to $url failed: " . $e->getMessage(), 0, $e);
		}catch(\JsonException $e){
			throw new \RuntimeException("Invalid JSON from $url: " . $e->getMessage(), 0, $e);
		}
	}

	/**
	 * @throws \RuntimeException
	 */
	private function getAuthServiceUri() : string{
		$json = self::fetchJson(self::MINECRAFT_SERVICES_DISCOVERY_URL);
		if(!is_object($json)){
			throw new \RuntimeException("Expected object from discovery, got " . gettype($json));
		}
		// Path: result.serviceEnvironments.auth.prod.serviceUri
		$uri = $json->result->serviceEnvironments->auth->prod->serviceUri ?? null;
		if(!is_string($uri)){
			throw new \RuntimeException("Missing serviceUri in discovery document");
		}
		return $uri;
	}

	/**
	 * @return array{string, string} [jwks_uri, issuer]
	 * @throws \RuntimeException
	 */
	private function getOpenIdConfig(string $authServiceUri) : array{
		$json = self::fetchJson($authServiceUri . self::AUTHORIZATION_SERVICE_OPENID_CONFIG_PATH);
		if(!is_object($json)){
			throw new \RuntimeException("Expected object from OpenID config, got " . gettype($json));
		}
		$jwksUri = $json->jwks_uri ?? null;
		$issuer  = $json->issuer ?? null;
		if(!is_string($jwksUri) || !is_string($issuer)){
			throw new \RuntimeException("Missing jwks_uri or issuer in OpenID config");
		}
		return [$jwksUri, $issuer];
	}

	/**
	 * Fetches the JWKS and converts RSA keys to DER format.
	 *
	 * @return array<string, string> kid => DER-encoded public key
	 * @throws \RuntimeException
	 */
	private function fetchDerKeys(string $jwksUri) : array{
		$json = self::fetchJson($jwksUri);
		$keysArray = null;
		if(is_object($json) && isset($json->keys) && is_array($json->keys)){
			$keysArray = $json->keys;
		}elseif(is_array($json) && isset($json["keys"]) && is_array($json["keys"])){
			$keysArray = $json["keys"];
		}
		if($keysArray === null){
			throw new \RuntimeException("Could not find 'keys' array in JWKS response");
		}

		$derKeys = [];
		foreach($keysArray as $key){
			$key = (object) $key;
			if(!isset($key->kid, $key->n, $key->e, $key->kty, $key->use)){
				continue;
			}
			if($key->use !== "sig" || $key->kty !== "RSA"){
				continue;
			}
			try{
				$derKeys[$key->kid] = \pocketmine\network\mcpe\JwtUtils::rsaPublicKeyModExpToDer($key->n, $key->e);
			}catch(\Throwable){
				// skip malformed key entries
			}
		}

		if($derKeys === []){
			throw new \RuntimeException("No valid RSA signing keys found in JWKS");
		}

		return $derKeys;
	}

	public function onCompletion() : void{
		/**
		 * @var \Closure $callback
		 * @phpstan-var \Closure(?array<string, string>, string, ?string[]) : void $callback
		 */
		$callback = $this->fetchLocal(self::KEYS_ON_COMPLETION);
		$callback($this->keys?->deserialize(), $this->issuer, $this->errors?->deserialize());
	}
}
