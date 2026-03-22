<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * Backported from PocketMine-MP 5.41.1
 * Replaces ProcessLoginTask for the self-signed / offline auth path.
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\auth;

use pocketmine\lang\KnownTranslationFactory;
use pocketmine\lang\Translatable;
use pocketmine\scheduler\AsyncTask;
use pocketmine\thread\NonThreadSafeValue;
use pocketmine\utils\AssumptionFailedError;
use function base64_decode;
use function igbinary_serialize;
use function igbinary_unserialize;

/**
 * Handles authentication for self-signed (offline / non-Xbox) login chains.
 * This is the legacy chain format still used by Bedrock clients not authenticated
 * via Xbox Live (AuthenticationType::SELF_SIGNED).
 *
 * Replaces ProcessLoginTask from PM4 – the main difference is that the callback
 * now accepts Translatable|string|null for the error, matching the new
 * VerifyLoginException and NetworkSession::setAuthenticationStatus() signature.
 */
class ProcessLegacyLoginTask extends AsyncTask{
	private const TLS_KEY_ON_COMPLETION = "completion";

	/**
	 * Mojang root public key (EC/secp384r1).
	 * Used to mark a chain as Xbox-authenticated.
	 * This is the "new" key deployed with 1.20.0.
	 */
	public const LEGACY_MOJANG_ROOT_PUBLIC_KEY = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECRXueJeTDqNRRgJi/vlRufByu/2G0i2Ebt6YMar5QX/R0DIIyrJMcUpruK4QveTfJSTp3Shlq4Gk34cD/4GUWwkv0DVuzeuB+tXija7HBxii03NHDbPAD0AKnLr2wdAp";

	/**
	 * Old Mojang root public key (kept for backwards compat with older clients).
	 */
	public const LEGACY_MOJANG_OLD_ROOT_PUBLIC_KEY = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8ELkixyLcwlZryUQcu1TvPOmI2B7vX83ndnWRUaXm74wFfa5f/lwQNTfrLVHa2PmenpGI6JhIMUJaWZrjmMj90NoKNFSNBuKdm8rYiXsfaz3K36x/1U26HpG0ZxK/V1V";

	private string $chain;

	/**
	 * Whether the keychain signatures were validated correctly.
	 * Non-null = error, player will be disconnected.
	 *
	 * @phpstan-var NonThreadSafeValue<Translatable>|string|null
	 */
	private NonThreadSafeValue|string|null $error = "Unknown";

	/** Whether the chain contains a link signed by the Mojang root key. */
	private bool $authenticated = false;

	private ?string $clientPublicKeyDer = null;

	/**
	 * @param string[] $chainJwts
	 * @phpstan-param \Closure(bool $isAuthenticated, bool $authRequired, Translatable|string|null $error, ?string $clientPublicKey) : void $onCompletion
	 */
	public function __construct(
		array $chainJwts,
		private string $clientDataJwt,
		private ?string $rootAuthKeyDer,
		private bool $authRequired,
		\Closure $onCompletion
	){
		$this->storeLocal(self::TLS_KEY_ON_COMPLETION, $onCompletion);
		$this->chain = igbinary_serialize($chainJwts) ?? throw new AssumptionFailedError("igbinary_serialize should never return null");
	}

	public function onRun() : void{
		try{
			$this->clientPublicKeyDer = $this->validateChain();
			AuthJwtHelper::validateSelfSignedToken($this->clientDataJwt, $this->clientPublicKeyDer);
			$this->error = null;
		}catch(VerifyLoginException $e){
			$msg = $e->getDisconnectMessage();
			$this->error = $msg instanceof Translatable ? new NonThreadSafeValue($msg) : $msg;
		}
	}

	private function validateChain() : string{
		/** @var string[] $chain */
		$chain = igbinary_unserialize($this->chain);

		$identityPublicKeyDer = null;

		foreach($chain as $jwt){
			$claims = AuthJwtHelper::validateLegacyAuthToken($jwt, $identityPublicKeyDer);

			// Check if this link was signed by the known Mojang root key
			if($this->rootAuthKeyDer !== null && $identityPublicKeyDer === $this->rootAuthKeyDer){
				$this->authenticated = true;
			}

			if(!isset($claims->identityPublicKey)){
				throw new VerifyLoginException(
					"Missing identityPublicKey in chain link",
					KnownTranslationFactory::pocketmine_disconnect_invalidSession_missingKey()
				);
			}

			$identityPublicKey = base64_decode($claims->identityPublicKey, true);
			if($identityPublicKey === false){
				throw new VerifyLoginException("Invalid identityPublicKey: base64 error decoding");
			}
			$identityPublicKeyDer = $identityPublicKey;
		}

		if($identityPublicKeyDer === null){
			throw new VerifyLoginException("No authentication chain links provided");
		}

		return $identityPublicKeyDer;
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

// Shim: keep old class name alive so any plugins that reference ProcessLoginTask still load
class_alias(ProcessLegacyLoginTask::class, 'pocketmine\network\mcpe\auth\ProcessLoginTask', false);
