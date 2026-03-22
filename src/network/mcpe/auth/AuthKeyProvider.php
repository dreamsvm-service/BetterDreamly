<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * Backported from PocketMine-MP 5.41.1
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\auth;

use pocketmine\promise\Promise;
use pocketmine\promise\PromiseResolver;
use pocketmine\scheduler\AsyncPool;
use pocketmine\utils\AssumptionFailedError;
use function array_keys;
use function count;
use function implode;
use function time;

/**
 * Manages Mojang's RSA public keys used to verify OpenID tokens from Bedrock 1.26.0+ clients.
 *
 * Keys are fetched asynchronously from Mojang's key server and cached for up to
 * ALLOWED_REFRESH_INTERVAL seconds. If an unrecognised key ID is encountered after
 * that interval, a fresh fetch is triggered.
 *
 * Backported from PM5.41.1 - new in Bedrock 1.26.0 auth flow.
 */
class AuthKeyProvider{
	/** Minimum time between key refreshes (30 minutes). */
	private const ALLOWED_REFRESH_INTERVAL = 30 * 60;

	private ?AuthKeyring $keyring = null;

	/** @phpstan-var PromiseResolver<AuthKeyring>|null */
	private ?PromiseResolver $resolver = null;

	private int $lastFetch = 0;

	public function __construct(
		private readonly \Logger $logger,
		private readonly AsyncPool $asyncPool,
		private readonly int $keyRefreshIntervalSeconds = self::ALLOWED_REFRESH_INTERVAL
	){}

	/**
	 * Returns a Promise that resolves with [issuer, derPublicKey] for the given key ID.
	 *
	 * @phpstan-return Promise<array{string, string}>
	 */
	public function getKey(string $keyId) : Promise{
		/** @phpstan-var PromiseResolver<array{string, string}> $resolver */
		$resolver = new PromiseResolver();

		$needsFetch =
			$this->keyring === null ||
			($this->keyring->getKey($keyId) === null && $this->lastFetch < time() - $this->keyRefreshIntervalSeconds);

		if($needsFetch){
			$this->fetchKeys()->onCompletion(
				onSuccess: fn(AuthKeyring $newKeyring) => $this->resolveKey($resolver, $newKeyring, $keyId),
				onFailure: $resolver->reject(...)
			);
		}else{
			$this->resolveKey($resolver, $this->keyring, $keyId);
		}

		return $resolver->getPromise();
	}

	/**
	 * @phpstan-param PromiseResolver<array{string, string}> $resolver
	 */
	private function resolveKey(PromiseResolver $resolver, AuthKeyring $keyring, string $keyId) : void{
		$key = $keyring->getKey($keyId);
		if($key === null){
			$this->logger->debug("Auth key '$keyId' not found in keyring");
			$resolver->reject();
			return;
		}
		$this->logger->debug("Auth key '$keyId' found in keyring (issuer: " . $keyring->getIssuer() . ")");
		$resolver->resolve([$keyring->getIssuer(), $key]);
	}

	/**
	 * @phpstan-return Promise<AuthKeyring>
	 */
	private function fetchKeys() : Promise{
		if($this->resolver !== null){
			$this->logger->debug("Key refresh already in progress, reusing existing promise");
			return $this->resolver->getPromise();
		}

		$this->logger->notice("Fetching Mojang authentication keys from discovery endpoint...");

		/** @phpstan-var PromiseResolver<AuthKeyring> $resolver */
		$resolver = new PromiseResolver();
		$this->resolver = $resolver;

		$this->asyncPool->submitTask(new FetchAuthKeysTask($this->onKeysFetched(...)));

		return $this->resolver->getPromise();
	}

	/**
	 * @phpstan-param array<string, string>|null $keys DER keys indexed by kid
	 * @phpstan-param string[]|null $errors
	 */
	private function onKeysFetched(?array $keys, string $issuer, ?array $errors) : void{
		$resolver = $this->resolver;
		if($resolver === null){
			throw new AssumptionFailedError("onKeysFetched called without a pending resolver");
		}

		try{
			if($errors !== null){
				$this->logger->warning("Errors while fetching auth keys:\n\t- " . implode("\n\t- ", $errors));
			}

			if($keys === null){
				$this->logger->critical(
					"Failed to fetch Mojang authentication keys. Xbox Live players may not be able to join."
				);
				$resolver->reject();
			}else{
				$this->logger->info(
					"Fetched " . count($keys) . " auth key(s) from issuer '$issuer': " . implode(", ", array_keys($keys))
				);
				$this->keyring = new AuthKeyring($issuer, $keys);
				$this->lastFetch = time();
				$resolver->resolve($this->keyring);
			}
		}finally{
			$this->resolver = null;
		}
	}
}
