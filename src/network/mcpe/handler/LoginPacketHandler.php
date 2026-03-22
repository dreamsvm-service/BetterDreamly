<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * Backported/adapted from PocketMine-MP 5.41.1
 *
 * PLUGIN API 4 COMPATIBILITY:
 *   - Class name, namespace, and constructor signature are unchanged.
 *   - handleLogin(), fetchAuthData(), parseClientData(), processLogin() remain present.
 *   - New methods (processOpenIdLogin, processSelfSignedLogin) are additive only.
 *   - Plugins that extend or call this class via the old API continue to work.
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\handler;

use pocketmine\entity\InvalidSkinException;
use pocketmine\event\player\PlayerPreLoginEvent;
use pocketmine\lang\KnownTranslationKeys;
use pocketmine\lang\Translatable;
use pocketmine\network\mcpe\auth\ProcessLegacyLoginTask;
use pocketmine\network\mcpe\auth\ProcessOpenIdLoginTask;
use pocketmine\network\mcpe\JwtException;
use pocketmine\network\mcpe\JwtUtils;
use pocketmine\network\mcpe\NetworkSession;
use pocketmine\network\mcpe\convert\SkinAdapterSingleton;
use pocketmine\network\mcpe\protocol\LoginPacket;
use pocketmine\network\mcpe\protocol\types\login\AuthenticationData;
use pocketmine\network\mcpe\protocol\types\login\ClientData;
use pocketmine\network\mcpe\protocol\types\login\ClientDataToSkinDataHelper;
use pocketmine\network\mcpe\protocol\types\login\JwtChain;
use pocketmine\network\PacketHandlingException;
use pocketmine\player\Player;
use pocketmine\player\PlayerInfo;
use pocketmine\player\XboxLivePlayerInfo;
use pocketmine\Server;
use Ramsey\Uuid\Uuid;
use function base64_decode;
use function chr;
use function is_array;
use function is_object;
use function is_string;
use function json_decode;
use function md5;
use function ord;
use function substr;
use const JSON_THROW_ON_ERROR;

/**
 * Handles the initial login phase of the session.
 *
 * Supports both authentication modes introduced by Bedrock 1.26.0:
 *  - AuthenticationType::FULL (OpenID Connect via Xbox Live)
 *  - AuthenticationType::SELF_SIGNED (legacy EC chain, offline players)
 *
 * API 4 compatibility: The legacy handleLogin() path still works for plugins
 * that override or hook this class.
 */
class LoginPacketHandler extends PacketHandler{

	/**
	 * @phpstan-param \Closure(PlayerInfo) : void $playerInfoConsumer
	 * @phpstan-param \Closure(bool $isAuthenticated, bool $authRequired, Translatable|string|null $error, ?string $clientPubKey) : void $authCallback
	 */
	public function __construct(
		private Server $server,
		private NetworkSession $session,
		private \Closure $playerInfoConsumer,
		private \Closure $authCallback
	){}

	public function handleLogin(LoginPacket $packet) : bool{
		// ── Bedrock 1.26.0 path: packet has authInfoJson ──────────────────────
		if(isset($packet->authInfoJson) && $packet->authInfoJson !== ""){
			return $this->handleLoginV2($packet);
		}

		// ── Legacy path (pre-1.26.0 / API-4 compatible) ───────────────────────
		return $this->handleLoginLegacy($packet);
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Bedrock 1.26.0 login (OpenID or self-signed, chosen by AuthenticationType)
	// ─────────────────────────────────────────────────────────────────────────

	private function handleLoginV2(LoginPacket $packet) : bool{
		try{
			$authInfo = json_decode($packet->authInfoJson, associative: false, flags: JSON_THROW_ON_ERROR);
		}catch(\JsonException $e){
			throw PacketHandlingException::wrap($e, "Failed to decode authInfoJson");
		}

		if(!is_object($authInfo)){
			throw new PacketHandlingException("authInfoJson must be a JSON object");
		}

		$type      = $authInfo->AuthenticationType ?? null;
		$token     = $authInfo->Token ?? null;
		$certChain = $authInfo->Certificate ?? null;

		// ── FULL: OpenID Connect (Xbox Live authenticated) ─────────────────
		if($type === "FULL" && is_string($token)){
			try{
				[$headerArray, ] = JwtUtils::parse($token);
			}catch(JwtException $e){
				throw PacketHandlingException::wrap($e, "Failed to parse OpenID token header");
			}

			$keyId = $headerArray["kid"] ?? null;
			if(!is_string($keyId)){
				throw new PacketHandlingException("Missing 'kid' in OpenID token header");
			}

			// Parse identity info from the token body (xid = XUID, xname = gamertag)
			try{
				[, $bodyArray, ] = JwtUtils::parse($token);
			}catch(JwtException $e){
				throw PacketHandlingException::wrap($e, "Failed to parse OpenID token body");
			}

			$xuid     = $bodyArray["xid"]   ?? "";
			$username = $bodyArray["xname"] ?? "";

			if(!is_string($username) || !Player::isValidUserName($username)){
				$this->session->disconnect(KnownTranslationKeys::DISCONNECTIONSCREEN_INVALIDNAME);
				return true;
			}

			// Derive a deterministic UUID from XUID (matches PM5 behaviour)
			$legacyUuid = is_string($xuid) && $xuid !== ""
				? $this->calculateUuidFromXuid($xuid)
				: Uuid::uuid4()->toString();

			// Build PlayerInfo
			$clientData = $this->parseClientData($packet->clientDataJwt);
			$skin = $this->buildSkin($clientData);
			if($skin === null){
				return true; // already disconnected
			}

			if(is_string($xuid) && $xuid !== ""){
				$playerInfo = new XboxLivePlayerInfo($xuid, $username, Uuid::fromString($legacyUuid), $skin, $clientData->LanguageCode, (array) $clientData);
			}else{
				$playerInfo = new PlayerInfo($username, Uuid::fromString($legacyUuid), $skin, $clientData->LanguageCode, (array) $clientData);
			}

			$preLoginResult = $this->doPreLoginEvent($playerInfo);
			if($preLoginResult === null){
				return true;
			}

			($this->playerInfoConsumer)($playerInfo);
			$this->processOpenIdLogin($token, $keyId, $packet->clientDataJwt, $preLoginResult);
			return true;
		}

		// ── SELF_SIGNED: legacy chain, offline / non-Xbox ─────────────────
		if($type === "SELF_SIGNED" && is_string($certChain)){
			try{
				$chainData = json_decode($certChain, flags: JSON_THROW_ON_ERROR);
			}catch(\JsonException $e){
				throw PacketHandlingException::wrap($e, "Failed to parse self-signed certificate chain");
			}

			if(!is_object($chainData) || !isset($chainData->chain) || !is_array($chainData->chain)){
				throw new PacketHandlingException("Invalid self-signed certificate chain structure");
			}

			$chainJwts = $chainData->chain;

			// Parse identity from the first (self-signed) chain link
			try{
				[, $claimsArray, ] = JwtUtils::parse($chainJwts[0] ?? "");
			}catch(JwtException $e){
				throw PacketHandlingException::wrap($e, "Failed to parse self-signed certificate");
			}

			$extraData = $claimsArray["extraData"] ?? null;
			if(!is_array($extraData)){
				throw new PacketHandlingException("Missing extraData in self-signed certificate");
			}

			$username = $extraData["displayName"] ?? "";
			$identity = $extraData["identity"] ?? "";

			if(!is_string($username) || !Player::isValidUserName($username)){
				$this->session->disconnect(KnownTranslationKeys::DISCONNECTIONSCREEN_INVALIDNAME);
				return true;
			}

			if(!is_string($identity) || !Uuid::isValid($identity)){
				throw new PacketHandlingException("Invalid UUID in self-signed extraData");
			}

			$clientData = $this->parseClientData($packet->clientDataJwt);
			$skin = $this->buildSkin($clientData);
			if($skin === null){
				return true;
			}

			$playerInfo = new PlayerInfo($username, Uuid::fromString($identity), $skin, $clientData->LanguageCode, (array) $clientData);

			$preLoginResult = $this->doPreLoginEvent($playerInfo);
			if($preLoginResult === null){
				return true;
			}

			($this->playerInfoConsumer)($playerInfo);
			$this->processSelfSignedLogin($chainJwts, $packet->clientDataJwt, $preLoginResult);
			return true;
		}

		throw new PacketHandlingException("Unsupported AuthenticationType: " . ($type ?? "(null)"));
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Legacy login path (pre-1.26.0, kept for API 4 compatibility)
	// ─────────────────────────────────────────────────────────────────────────

	private function handleLoginLegacy(LoginPacket $packet) : bool{
		$extraData = $this->fetchAuthData($packet->chainDataJwt);

		if(!Player::isValidUserName($extraData->displayName)){
			$this->session->disconnect(KnownTranslationKeys::DISCONNECTIONSCREEN_INVALIDNAME);
			return true;
		}

		$clientData = $this->parseClientData($packet->clientDataJwt);

		$skin = $this->buildSkin($clientData);
		if($skin === null){
			return true;
		}

		if(!Uuid::isValid($extraData->identity)){
			throw new PacketHandlingException("Invalid login UUID");
		}
		$uuid = Uuid::fromString($extraData->identity);

		if($extraData->XUID !== ""){
			$playerInfo = new XboxLivePlayerInfo(
				$extraData->XUID, $extraData->displayName, $uuid,
				$skin, $clientData->LanguageCode, (array) $clientData
			);
		}else{
			$playerInfo = new PlayerInfo(
				$extraData->displayName, $uuid,
				$skin, $clientData->LanguageCode, (array) $clientData
			);
		}

		($this->playerInfoConsumer)($playerInfo);

		$ev = new PlayerPreLoginEvent(
			$playerInfo,
			$this->session->getIp(),
			$this->session->getPort(),
			$this->server->requiresAuthentication()
		);
		if($this->server->getNetwork()->getValidConnectionCount() > $this->server->getMaxPlayers()){
			$ev->setKickReason(PlayerPreLoginEvent::KICK_REASON_SERVER_FULL, KnownTranslationKeys::DISCONNECTIONSCREEN_SERVERFULL);
		}
		if(!$this->server->isWhitelisted($playerInfo->getUsername())){
			$ev->setKickReason(PlayerPreLoginEvent::KICK_REASON_SERVER_WHITELISTED, "Server is whitelisted");
		}
		if($this->server->getNameBans()->isBanned($playerInfo->getUsername()) || $this->server->getIPBans()->isBanned($this->session->getIp())){
			$ev->setKickReason(PlayerPreLoginEvent::KICK_REASON_BANNED, "You are banned");
		}

		$ev->call();
		if(!$ev->isAllowed()){
			$this->session->disconnect($ev->getFinalKickMessage());
			return true;
		}

		$this->processLogin($packet, $ev->isAuthRequired());
		return true;
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Shared helpers
	// ─────────────────────────────────────────────────────────────────────────

	private function buildSkin(ClientData $clientData) : ?\pocketmine\entity\Skin{
		try{
			return SkinAdapterSingleton::get()->fromSkinData(ClientDataToSkinDataHelper::fromClientData($clientData));
		}catch(\InvalidArgumentException | InvalidSkinException $e){
			$this->session->getLogger()->debug("Invalid skin: " . $e->getMessage());
			$this->session->disconnect(KnownTranslationKeys::DISCONNECTIONSCREEN_INVALIDSKIN);
			return null;
		}
	}

	/**
	 * Run the PlayerPreLoginEvent. Returns auth-required bool or null if the login was cancelled.
	 */
	private function doPreLoginEvent(PlayerInfo $playerInfo) : ?bool{
		$ev = new PlayerPreLoginEvent(
			$playerInfo,
			$this->session->getIp(),
			$this->session->getPort(),
			$this->server->requiresAuthentication()
		);
		if($this->server->getNetwork()->getValidConnectionCount() > $this->server->getMaxPlayers()){
			$ev->setKickReason(PlayerPreLoginEvent::KICK_REASON_SERVER_FULL, KnownTranslationKeys::DISCONNECTIONSCREEN_SERVERFULL);
		}
		if(!$this->server->isWhitelisted($playerInfo->getUsername())){
			$ev->setKickReason(PlayerPreLoginEvent::KICK_REASON_SERVER_WHITELISTED, "Server is whitelisted");
		}
		if($this->server->getNameBans()->isBanned($playerInfo->getUsername()) || $this->server->getIPBans()->isBanned($this->session->getIp())){
			$ev->setKickReason(PlayerPreLoginEvent::KICK_REASON_BANNED, "You are banned");
		}
		$ev->call();
		if(!$ev->isAllowed()){
			$this->session->disconnect($ev->getFinalKickMessage());
			return null;
		}
		return $ev->isAuthRequired();
	}

	/**
	 * Derives a stable UUID v3 from an XUID string, matching PM5 behaviour so that
	 * player data files are consistent between auth systems.
	 */
	private function calculateUuidFromXuid(string $xuid) : string{
		// MD5 of "xuid:" + xuid, then format as UUID v3
		$hash = md5("xuid:" . $xuid);
		// Set version bits (v3) and variant bits
		$hash[12] = "3";
		$hash[16] = dechex((hexdec($hash[16]) & 0x3) | 0x8);
		return substr($hash, 0, 8) . "-" . substr($hash, 8, 4) . "-" . substr($hash, 12, 4) . "-" . substr($hash, 16, 4) . "-" . substr($hash, 20);
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Auth submission (kept compatible with API 4 plugins)
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * Submits an OpenID login for async verification.
	 * New in BetterDreamly (backported from PM5.41.1).
	 */
	protected function processOpenIdLogin(string $token, string $keyId, string $clientDataJwt, bool $authRequired) : void{
		$this->session->setHandler(null); // drop packets during verification

		$this->server->getAuthKeyProvider()->getKey($keyId)->onCompletion(
			function(array $issuerAndKey) use ($token, $clientDataJwt, $authRequired) : void{
				[$issuer, $mojangPublicKeyDer] = $issuerAndKey;
				$this->server->getAsyncPool()->submitTask(
					new ProcessOpenIdLoginTask($token, $issuer, $mojangPublicKeyDer, $clientDataJwt, $authRequired, $this->authCallback)
				);
			},
			fn() => ($this->authCallback)(false, $authRequired, "Unrecognized authentication key ID: $keyId", null)
		);
	}

	/**
	 * Submits a self-signed (offline) login for async verification.
	 * New in BetterDreamly (backported from PM5.41.1).
	 *
	 * @param string[] $chainJwts
	 */
	protected function processSelfSignedLogin(array $chainJwts, string $clientDataJwt, bool $authRequired) : void{
		$this->session->setHandler(null);

		$rootKey = base64_decode(ProcessLegacyLoginTask::LEGACY_MOJANG_ROOT_PUBLIC_KEY, true) ?: null;

		$this->server->getAsyncPool()->submitTask(
			new ProcessLegacyLoginTask($chainJwts, $clientDataJwt, rootAuthKeyDer: $rootKey, authRequired: $authRequired, onCompletion: $this->authCallback)
		);
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Legacy API 4 methods — kept intact so plugins can still call/override them
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * @throws PacketHandlingException
	 */
	protected function fetchAuthData(JwtChain $chain) : AuthenticationData{
		/** @var AuthenticationData|null $extraData */
		$extraData = null;
		foreach($chain->chain as $jwt){
			try{
				[, $claims, ] = JwtUtils::parse($jwt);
			}catch(JwtException $e){
				throw PacketHandlingException::wrap($e);
			}
			if(isset($claims["extraData"])){
				if($extraData !== null){
					throw new PacketHandlingException("Found 'extraData' more than once in chainData");
				}
				if(!is_array($claims["extraData"])){
					throw new PacketHandlingException("'extraData' key should be an array");
				}
				$mapper = new \JsonMapper();
				$mapper->bEnforceMapType = false;
				$mapper->bExceptionOnMissingData = true;
				$mapper->bExceptionOnUndefinedProperty = true;
				try{
					/** @var AuthenticationData $extraData */
					$extraData = $mapper->map($claims["extraData"], new AuthenticationData());
				}catch(\JsonMapper_Exception $e){
					throw PacketHandlingException::wrap($e);
				}
			}
		}
		if($extraData === null){
			throw new PacketHandlingException("'extraData' not found in chain data");
		}
		return $extraData;
	}

	/**
	 * @throws PacketHandlingException
	 */
	protected function parseClientData(string $clientDataJwt) : ClientData{
		try{
			[, $clientDataClaims, ] = JwtUtils::parse($clientDataJwt);
		}catch(JwtException $e){
			throw PacketHandlingException::wrap($e);
		}

		$mapper = new \JsonMapper();
		$mapper->bEnforceMapType = false;
		$mapper->bExceptionOnMissingData = true;
		$mapper->bExceptionOnUndefinedProperty = true;
		try{
			$clientData = $mapper->map($clientDataClaims, new ClientData());
		}catch(\JsonMapper_Exception $e){
			throw PacketHandlingException::wrap($e);
		}
		return $clientData;
	}

	/**
	 * Legacy processLogin — submits old-style chain auth.
	 * Kept for plugin compatibility (e.g. Specter, SpecterExt).
	 *
	 * @throws \InvalidArgumentException
	 */
	protected function processLogin(LoginPacket $packet, bool $authRequired) : void{
		$rootKey = base64_decode(ProcessLegacyLoginTask::LEGACY_MOJANG_ROOT_PUBLIC_KEY, true) ?: null;
		$this->server->getAsyncPool()->submitTask(
			new ProcessLegacyLoginTask(
				$packet->chainDataJwt->chain,
				$packet->clientDataJwt,
				rootAuthKeyDer: $rootKey,
				authRequired: $authRequired,
				onCompletion: $this->authCallback
			)
		);
		$this->session->setHandler(null);
	}
}
