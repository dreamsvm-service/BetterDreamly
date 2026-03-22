<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * Backported from PocketMine-MP 5.41.1
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\auth;

use pocketmine\lang\Translatable;
use pocketmine\scheduler\AsyncTask;
use pocketmine\thread\NonThreadSafeValue;
use function base64_decode;

/**
 * Validates an OpenID Connect auth token sent by Bedrock 1.26.0+ clients
 * (AuthenticationType::FULL). The token is an RSA-signed JWT issued by
 * Mojang's authorization service.
 *
 * New in Bedrock 1.26.0 - not present in PM4.
 */
class ProcessOpenIdLoginTask extends AsyncTask{
	private const TLS_KEY_ON_COMPLETION = "completion";

	/**
	 * The expected audience claim in the OpenID JWT.
	 * This must match what Mojang's auth service issues.
	 */
	public const MOJANG_AUDIENCE = "api://auth-minecraft-services/multiplayer";

	/**
	 * @phpstan-var NonThreadSafeValue<Translatable>|string|null
	 */
	private NonThreadSafeValue|string|null $error = "Unknown";

	private bool $authenticated = false;
	private ?string $clientPublicKeyDer = null;

	/**
	 * @phpstan-param \Closure(bool $isAuthenticated, bool $authRequired, Translatable|string|null $error, ?string $clientPublicKey) : void $onCompletion
	 */
	public function __construct(
		private string $jwt,
		private string $issuer,
		private string $mojangPublicKeyDer,
		private string $clientDataJwt,
		private bool $authRequired,
		\Closure $onCompletion
	){
		$this->storeLocal(self::TLS_KEY_ON_COMPLETION, $onCompletion);
	}

	public function onRun() : void{
		try{
			$this->clientPublicKeyDer = $this->validateChain();
			$this->error = null;
		}catch(VerifyLoginException $e){
			$msg = $e->getDisconnectMessage();
			$this->error = $msg instanceof Translatable ? new NonThreadSafeValue($msg) : $msg;
		}
	}

	private function validateChain() : string{
		$claims = AuthJwtHelper::validateOpenIdAuthToken(
			$this->jwt,
			$this->mojangPublicKeyDer,
			issuer: $this->issuer,
			audience: self::MOJANG_AUDIENCE
		);

		// Validated against Mojang's key server = Xbox authenticated
		$this->authenticated = true;

		// cpk = client public key (EC), used to verify the clientDataJwt
		if(!isset($claims->cpk)){
			throw new VerifyLoginException("Missing cpk claim in OpenID token");
		}

		$clientDerKey = base64_decode($claims->cpk, strict: true);
		if($clientDerKey === false){
			throw new VerifyLoginException("Invalid cpk claim: base64 decoding error");
		}

		// Validate the clientDataJwt is signed by the client's key
		AuthJwtHelper::validateSelfSignedToken($this->clientDataJwt, $clientDerKey);

		return $clientDerKey;
	}

	public function onCompletion() : void{
		/**
		 * @var \Closure $callback
		 * @phpstan-var \Closure(bool, bool, Translatable|string|null, ?string) : void $callback
		 */
		$callback = $this->fetchLocal(self::TLS_KEY_ON_COMPLETION);
		$callback(
			$this->authenticated,
			$this->authRequired,
			$this->error instanceof NonThreadSafeValue ? $this->error->deserialize() : $this->error,
			$this->clientPublicKeyDer
		);
	}
}
