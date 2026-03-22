<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * Modified from PM4 to accept protocol 800 (Bedrock 1.26.0).
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\handler;

use pocketmine\lang\KnownTranslationFactory;
use pocketmine\network\mcpe\NetworkSession;
use pocketmine\network\mcpe\protocol\NetworkSettingsPacket;
use pocketmine\network\mcpe\protocol\PlayStatusPacket;
use pocketmine\network\mcpe\protocol\ProtocolInfo;
use pocketmine\network\mcpe\protocol\RequestNetworkSettingsPacket;
use pocketmine\network\mcpe\protocol\types\CompressionAlgorithm;
use pocketmine\Server;

/**
 * Handles the very first packet in a session: RequestNetworkSettings.
 *
 * Changes from PM4:
 *  - Protocol version check now passes for CURRENT_PROTOCOL = 800 (Bedrock 1.26.0).
 *  - All other behaviour is identical to PM4.
 */
final class SessionStartPacketHandler extends PacketHandler{

	/**
	 * @phpstan-param \Closure() : void $onSuccess
	 */
	public function __construct(
		private Server $server,
		private NetworkSession $session,
		private \Closure $onSuccess
	){}

	public function handleRequestNetworkSettings(RequestNetworkSettingsPacket $packet) : bool{
		$protocolVersion = $packet->getProtocolVersion();
		if(!$this->isCompatibleProtocol($protocolVersion)){
			$this->session->sendDataPacket(
				PlayStatusPacket::create(
					$protocolVersion < ProtocolInfo::CURRENT_PROTOCOL
						? PlayStatusPacket::LOGIN_FAILED_CLIENT
						: PlayStatusPacket::LOGIN_FAILED_SERVER
				),
				true
			);

			$this->session->disconnect(
				$this->server->getLanguage()->translate(
					KnownTranslationFactory::pocketmine_disconnect_incompatibleProtocol((string) $protocolVersion)
				),
				false
			);

			return true;
		}

		$this->session->sendDataPacket(NetworkSettingsPacket::create(
			NetworkSettingsPacket::COMPRESS_EVERYTHING,
			CompressionAlgorithm::ZLIB,
			false,
			0,
			0
		));

		($this->onSuccess)();
		return true;
	}

	protected function isCompatibleProtocol(int $protocolVersion) : bool{
		return $protocolVersion === ProtocolInfo::CURRENT_PROTOCOL;
	}
}
