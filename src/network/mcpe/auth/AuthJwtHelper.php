<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * Backported from PocketMine-MP 5.41.1
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe\auth;

use pocketmine\lang\KnownTranslationFactory;
use pocketmine\lang\Translatable;
use pocketmine\network\mcpe\JwtException;
use pocketmine\network\mcpe\JwtUtils;
use function base64_decode;
use function time;

/**
 * Helper class for validating JWTs in both legacy (EC/secp384r1 chain) and
 * OpenID (RSA) authentication flows used by Bedrock 1.26.0+ clients.
 *
 * Backported from PM5.41.1 - replaces the inline logic in ProcessLoginTask.
 */
final class AuthJwtHelper{

	private const CLOCK_DRIFT_MAX = 60;

	/**
	 * Validates an OpenID auth token signed with an RSA key from Mojang's key server.
	 * Used by Bedrock 1.26.0+ clients (AuthenticationType::FULL).
	 *
	 * @throws VerifyLoginException
	 */
	public static function validateOpenIdAuthToken(string $jwt, string $signingKeyDer, string $issuer, string $audience) : object{
		try{
			if(!JwtUtils::verifyRsa($jwt, $signingKeyDer)){
				throw new VerifyLoginException(
					"Invalid JWT signature",
					KnownTranslationFactory::pocketmine_disconnect_invalidSession_badSignature()
				);
			}
		}catch(JwtException $e){
			throw new VerifyLoginException($e->getMessage(), null, 0, $e);
		}

		try{
			[, $claimsArray, ] = JwtUtils::parse($jwt);
		}catch(JwtException $e){
			throw new VerifyLoginException("Failed to parse JWT: " . $e->getMessage(), null, 0, $e);
		}

		$mapper = new \JsonMapper();
		$mapper->bExceptionOnUndefinedProperty = false;
		$mapper->bExceptionOnMissingData = true;
		$mapper->bEnforceMapType = false;
		$mapper->bRemoveUndefinedAttributes = true;

		try{
			$claims = $mapper->map((object) $claimsArray, new \stdClass());
		}catch(\JsonMapper_Exception $e){
			throw new VerifyLoginException("Invalid auth token body: " . $e->getMessage(), null, 0, $e);
		}

		if(!isset($claims->iss) || $claims->iss !== $issuer){
			throw new VerifyLoginException("Invalid JWT issuer");
		}

		if(!isset($claims->aud) || $claims->aud !== $audience){
			throw new VerifyLoginException("Invalid JWT audience");
		}

		self::checkExpiry($claims);

		return $claims;
	}

	/**
	 * Validates a legacy EC-signed auth token (self-signed chain, offline/non-Xbox players).
	 * Used by Bedrock clients that are not authenticated via Xbox Live.
	 *
	 * @throws VerifyLoginException
	 */
	public static function validateLegacyAuthToken(string $jwt, ?string $expectedKeyDer) : object{
		self::validateSelfSignedToken($jwt, $expectedKeyDer);

		try{
			[, $claimsArray, ] = JwtUtils::parse($jwt);
		}catch(JwtException $e){
			throw new VerifyLoginException("Failed to parse JWT: " . $e->getMessage(), null, 0, $e);
		}

		$mapper = new \JsonMapper();
		$mapper->bExceptionOnUndefinedProperty = false;
		$mapper->bExceptionOnMissingData = true;
		$mapper->bEnforceMapType = false;
		$mapper->bRemoveUndefinedAttributes = true;

		try{
			$claims = $mapper->map((object) $claimsArray, new \stdClass());
		}catch(\JsonMapper_Exception $e){
			throw new VerifyLoginException("Invalid chain link body: " . $e->getMessage(), null, 0, $e);
		}

		self::checkExpiry($claims);

		return $claims;
	}

	/**
	 * Validates that a JWT is self-signed with the EC key declared in its own x5u header.
	 * Used for both legacy chain links and client data JWT.
	 *
	 * @throws VerifyLoginException
	 */
	public static function validateSelfSignedToken(string $jwt, ?string $expectedKeyDer) : void{
		try{
			[$headersArray, , ] = JwtUtils::parse($jwt);
		}catch(JwtException $e){
			throw new VerifyLoginException("Failed to parse JWT: " . $e->getMessage(), null, 0, $e);
		}

		if(!isset($headersArray["x5u"]) || !is_string($headersArray["x5u"])){
			throw new VerifyLoginException("Missing or invalid x5u header in JWT");
		}

		$headerDerKey = base64_decode($headersArray["x5u"], true);
		if($headerDerKey === false){
			throw new VerifyLoginException("Invalid JWT public key: base64 decoding error decoding x5u");
		}

		if($expectedKeyDer !== null && $headerDerKey !== $expectedKeyDer){
			throw new VerifyLoginException(
				"Invalid JWT signature",
				KnownTranslationFactory::pocketmine_disconnect_invalidSession_badSignature()
			);
		}

		try{
			if(!JwtUtils::verifyEc($jwt, $headerDerKey)){
				throw new VerifyLoginException(
					"Invalid JWT signature",
					KnownTranslationFactory::pocketmine_disconnect_invalidSession_badSignature()
				);
			}
		}catch(JwtException $e){
			throw new VerifyLoginException($e->getMessage(), null, 0, $e);
		}
	}

	/**
	 * @throws VerifyLoginException if the token is expired or not yet valid
	 */
	private static function checkExpiry(object $claims) : void{
		$time = time();
		if(isset($claims->nbf) && $claims->nbf > $time + self::CLOCK_DRIFT_MAX){
			throw new VerifyLoginException(
				"JWT not yet valid",
				KnownTranslationFactory::pocketmine_disconnect_invalidSession_tooEarly()
			);
		}
		if(isset($claims->exp) && $claims->exp < $time - self::CLOCK_DRIFT_MAX){
			throw new VerifyLoginException(
				"JWT expired",
				KnownTranslationFactory::pocketmine_disconnect_invalidSession_tooLate()
			);
		}
	}
}
