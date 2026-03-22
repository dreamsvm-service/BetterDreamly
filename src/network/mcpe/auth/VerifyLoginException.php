<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * Protocol backport from PocketMine-MP 5.41.1
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\auth;

use pocketmine\lang\Translatable;

/**
 * Backported from PM5.41.1 to support both string and Translatable disconnect messages,
 * required by the OpenID authentication system used in Bedrock 1.26.0.
 */
class VerifyLoginException extends \RuntimeException{

	private Translatable|string $disconnectMessage;

	public function __construct(string $message, Translatable|string|null $disconnectMessage = null, int $code = 0, ?\Throwable $previous = null){
		parent::__construct($message, $code, $previous);
		$this->disconnectMessage = $disconnectMessage ?? $message;
	}

	public function getDisconnectMessage() : Translatable|string{
		return $this->disconnectMessage;
	}
}
