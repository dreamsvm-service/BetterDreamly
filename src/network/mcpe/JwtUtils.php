<?php

/*
 * BetterDreamly - Minecraft Bedrock 1.26.0 Server
 * Built on PocketMine-MP API 4 (engine: 4.26.0)
 *
 * Extended from PM4 JwtUtils to add:
 *   - verifyEc()  : EC key verification (original verify() behaviour)
 *   - verifyRsa() : RSA key verification (new, for OpenID tokens in 1.26.0)
 *   - rsaPublicKeyModExpToDer() : build DER key from JWK n+e fields
 *   - derPublicKeyToPem() : helper
 *
 * The original verify(\OpenSSLAsymmetricKey) signature is preserved for API 4
 * plugin compatibility.
 */

declare(strict_types=1);

namespace pocketmine\network\mcpe;

use FG\ASN1\Exception\ParserException;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\Sequence;
use pocketmine\utils\AssumptionFailedError;
use pocketmine\utils\Utils;
use function base64_decode;
use function base64_encode;
use function chr;
use function count;
use function explode;
use function gmp_export;
use function gmp_import;
use function gmp_init;
use function gmp_strval;
use function hex2bin;
use function is_array;
use function json_decode;
use function json_encode;
use function json_last_error_msg;
use function ltrim;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;
use function ord;
use function preg_match;
use function rtrim;
use function sprintf;
use function str_pad;
use function str_repeat;
use function str_replace;
use function str_split;
use function strlen;
use function strtr;
use function substr;
use const GMP_BIG_ENDIAN;
use const GMP_MSW_FIRST;
use const JSON_THROW_ON_ERROR;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const STR_PAD_LEFT;

final class JwtUtils{
	public const BEDROCK_SIGNING_KEY_CURVE_NAME = "secp384r1";

	/**
	 * @return string[]
	 * @phpstan-return array{string, string, string}
	 * @throws JwtException
	 */
	public static function split(string $jwt) : array{
		$parts = explode(".", $jwt, 4);
		if(count($parts) !== 3){
			throw new JwtException("Expected exactly 3 JWT parts, got " . count($parts));
		}
		return $parts;
	}

	/**
	 * @return array<int, mixed>
	 * @phpstan-return array{array<string, mixed>, array<string, mixed>, string}
	 * @throws JwtException
	 */
	public static function parse(string $token) : array{
		[$headerB64, $bodyB64, $sigB64] = self::split($token);

		$header = json_decode(self::b64UrlDecode($headerB64), true);
		if(!is_array($header)){
			throw new JwtException("Failed to decode JWT header: " . json_last_error_msg());
		}
		$body = json_decode(self::b64UrlDecode($bodyB64), true);
		if(!is_array($body)){
			throw new JwtException("Failed to decode JWT body: " . json_last_error_msg());
		}
		return [$header, $body, $sigB64];
	}

	// ─────────────────────────────────────────────────────────────────────────
	// EC verification (original PM4 path — kept for API compatibility)
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * Verify a JWT signed with an EC/secp384r1 key (legacy Bedrock chain format).
	 * Accepts the raw DER key as a string.
	 *
	 * @throws JwtException
	 */
	public static function verifyEc(string $jwt, string $signingKeyDer) : bool{
		$signingKey = self::parseDerPublicKey($signingKeyDer);
		return self::verify($jwt, $signingKey);
	}

	/**
	 * Original API 4 verify() — accepts an OpenSSLAsymmetricKey.
	 * Kept intact for plugin compatibility.
	 *
	 * @throws JwtException
	 */
	public static function verify(string $jwt, \OpenSSLAsymmetricKey $signingKey) : bool{
		[$header, $body, $signature] = self::split($jwt);

		$plainSignature = self::b64UrlDecode($signature);
		if(strlen($plainSignature) !== 96){
			throw new JwtException("JWT signature has unexpected length, expected 96, got " . strlen($plainSignature));
		}

		[$rString, $sString] = str_split($plainSignature, 48);
		$convert = fn(string $str) => gmp_strval(gmp_import($str, 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST), 10);

		$sequence = new Sequence(
			new Integer($convert($rString)),
			new Integer($convert($sString))
		);

		$v = openssl_verify(
			$header . '.' . $body,
			$sequence->getBinary(),
			$signingKey,
			OPENSSL_ALGO_SHA384
		);
		switch($v){
			case 0: return false;
			case 1: return true;
			case -1: throw new JwtException("Error verifying JWT signature: " . openssl_error_string());
			default: throw new AssumptionFailedError("openssl_verify() should only return -1, 0 or 1");
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// RSA verification (new in BetterDreamly — for OpenID tokens from 1.26.0)
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * Verify a JWT signed with an RSA key (Mojang's OpenID auth tokens, Bedrock 1.26.0+).
	 * Accepts the raw DER-encoded RSA public key.
	 *
	 * @throws JwtException
	 */
	public static function verifyRsa(string $jwt, string $signingKeyDer) : bool{
		[$header, $body, $signature] = self::split($jwt);

		$rawSignature = self::b64UrlDecode($signature);

		$opensslKey = openssl_pkey_get_public(self::derPublicKeyToPem($signingKeyDer));
		if($opensslKey === false){
			throw new JwtException("Failed to load RSA public key: " . openssl_error_string());
		}

		$v = openssl_verify(
			$header . '.' . $body,
			$rawSignature,
			$opensslKey,
			OPENSSL_ALGO_SHA256
		);
		switch($v){
			case 0: return false;
			case 1: return true;
			case -1: throw new JwtException("Error verifying RSA JWT signature: " . openssl_error_string());
			default: throw new AssumptionFailedError("openssl_verify() should only return -1, 0 or 1");
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Key utilities
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * @phpstan-param array<string, mixed> $header
	 * @phpstan-param array<string, mixed> $claims
	 */
	public static function create(array $header, array $claims, \OpenSSLAsymmetricKey $signingKey) : string{
		$jwtBody = JwtUtils::b64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR))
			. "."
			. JwtUtils::b64UrlEncode(json_encode($claims, JSON_THROW_ON_ERROR));

		openssl_sign($jwtBody, $rawDerSig, $signingKey, OPENSSL_ALGO_SHA384);

		try{
			$asnObject = Sequence::fromBinary($rawDerSig);
		}catch(ParserException $e){
			throw new AssumptionFailedError("Failed to parse OpenSSL signature: " . $e->getMessage(), 0, $e);
		}
		if(count($asnObject) !== 2){
			throw new AssumptionFailedError("OpenSSL produced invalid signature, expected exactly 2 parts");
		}
		[$r, $s] = [$asnObject[0], $asnObject[1]];
		if(!($r instanceof Integer) || !($s instanceof Integer)){
			throw new AssumptionFailedError("OpenSSL produced invalid signature, expected 2 INTEGER parts");
		}

		$toBinary = fn($str) => str_pad(
			gmp_export(gmp_init($str, 10), 1, GMP_BIG_ENDIAN | GMP_MSW_FIRST),
			48, "\x00", STR_PAD_LEFT
		);
		$jwtSig = JwtUtils::b64UrlEncode($toBinary($r->getContent()) . $toBinary($s->getContent()));

		return "$jwtBody.$jwtSig";
	}

	public static function b64UrlEncode(string $str) : string{
		return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
	}

	public static function b64UrlDecode(string $str) : string{
		if(($len = strlen($str) % 4) !== 0){
			$str .= str_repeat('=', 4 - $len);
		}
		$decoded = base64_decode(strtr($str, '-_', '+/'), true);
		if($decoded === false){
			throw new JwtException("Malformed base64url encoded payload could not be decoded");
		}
		return $decoded;
	}

	public static function emitDerPublicKey(\OpenSSLAsymmetricKey $opensslKey) : string{
		$details = Utils::assumeNotFalse(openssl_pkey_get_details($opensslKey), "Failed to get details from OpenSSL key resource");
		/** @var string $pemKey */
		$pemKey = $details['key'];
		if(preg_match("@^-----BEGIN[A-Z\d ]+PUBLIC KEY-----\n([A-Za-z\d+/\n]+)\n-----END[A-Z\d ]+PUBLIC KEY-----\n$@", $pemKey, $matches) === 1){
			$derKey = base64_decode(str_replace("\n", "", $matches[1]), true);
			if($derKey !== false){
				return $derKey;
			}
		}
		throw new AssumptionFailedError("OpenSSL resource contains invalid public key");
	}

	/**
	 * Parse a DER-encoded EC public key (secp384r1). Validates curve name.
	 *
	 * @throws JwtException
	 */
	public static function parseDerPublicKey(string $derKey) : \OpenSSLAsymmetricKey{
		$signingKeyOpenSSL = openssl_pkey_get_public(
			sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n", base64_encode($derKey))
		);
		if($signingKeyOpenSSL === false){
			throw new JwtException("OpenSSL failed to parse key: " . openssl_error_string());
		}
		$details = openssl_pkey_get_details($signingKeyOpenSSL);
		if($details === false){
			throw new JwtException("OpenSSL failed to get details from key: " . openssl_error_string());
		}
		if(!isset($details['ec']['curve_name'])){
			throw new JwtException("Expected an EC key");
		}
		$curve = $details['ec']['curve_name'];
		if($curve !== self::BEDROCK_SIGNING_KEY_CURVE_NAME){
			throw new JwtException("Key must belong to curve " . self::BEDROCK_SIGNING_KEY_CURVE_NAME . ", got $curve");
		}
		return $signingKeyOpenSSL;
	}

	/**
	 * Convert a DER-encoded public key to PEM format.
	 * Works for both EC and RSA keys.
	 */
	public static function derPublicKeyToPem(string $derKey) : string{
		return sprintf(
			"-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n",
			base64_encode($derKey)
		);
	}

	/**
	 * Build a DER-encoded RSA public key from Base64URL-encoded modulus and exponent.
	 * Used to convert JWKS entries (n, e fields) into a usable key for openssl_verify().
	 *
	 * Backported from PM5.41.1 — needed for OpenID token verification in Bedrock 1.26.0.
	 *
	 * @param string $nBase64 RSA modulus (Base64URL-encoded)
	 * @param string $eBase64 RSA public exponent (Base64URL-encoded)
	 * @throws JwtException on invalid Base64URL input
	 */
	public static function rsaPublicKeyModExpToDer(string $nBase64, string $eBase64) : string{
		$mod = self::b64UrlDecode($nBase64);
		$exp = self::b64UrlDecode($eBase64);

		// Ensure positive integers (add leading 0x00 if high bit is set)
		if(ord($mod[0]) >= 0x80) $mod = "\x00" . $mod;
		if(ord($exp[0]) >= 0x80) $exp = "\x00" . $exp;

		$modulus        = self::encodeDerTlv(0x02, $mod);
		$publicExponent = self::encodeDerTlv(0x02, $exp);
		$rsaPublicKey   = self::encodeDerTlv(0x30, $modulus . $publicExponent);

		// RSA OID: 1.2.840.113549.1.1.1, parameters: NULL
		$rsaOid = hex2bin('300d06092a864886f70d0101010500');

		// Wrap in BIT STRING (tag 0x03), prepend 0x00 (no unused bits)
		$bitString = self::encodeDerTlv(0x03, "\x00" . $rsaPublicKey);

		// Outer SEQUENCE: algorithm identifier + bit string
		return self::encodeDerTlv(0x30, $rsaOid . $bitString);
	}

	/**
	 * Encode a DER TLV (Tag-Length-Value) tuple.
	 *
	 * @phpstan-param int<0, 255> $tag
	 */
	private static function encodeDerTlv(int $tag, string $value) : string{
		return chr($tag) . self::encodeDerLength(strlen($value)) . $value;
	}

	/**
	 * Encode a DER length field.
	 *
	 * @phpstan-param 0|positive-int $length
	 */
	private static function encodeDerLength(int $length) : string{
		if($length <= 0x7F){
			return chr($length);
		}
		// Long form: first byte = 0x80 | number of length bytes
		$lengthBytes = ltrim(pack("N", $length), "\x00");
		return chr(0x80 | strlen($lengthBytes)) . $lengthBytes;
	}
}
