<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * Backported from PocketMine-MP 5.41.1
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\auth;

/**
 * Holds Mojang's public keys (fetched at runtime via OpenID discovery),
 * indexed by key ID. Used for verifying OpenID auth tokens sent by
 * Bedrock 1.26.0+ clients.
 */
final class AuthKeyring{

	/**
	 * @param string[] $keys DER-encoded public keys indexed by key ID
	 * @phpstan-param array<string, string> $keys
	 */
	public function __construct(
		private string $issuer,
		private array $keys
	){}

	public function getIssuer() : string{
		return $this->issuer;
	}

	/**
	 * Returns the raw DER public key for the given key ID, or null if not found.
	 */
	public function getKey(string $keyId) : ?string{
		return $this->keys[$keyId] ?? null;
	}
}
