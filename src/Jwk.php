<?php

declare(strict_types=1);

namespace Sclemance\Oidc;

use Sclemance\Oidc\Exception\AuthenticationException;

/**
 * Converts an RSA JSON Web Key (JWK) into a PEM public key, with no dependency on phpseclib.
 *
 * We build the SubjectPublicKeyInfo DER structure by hand from the modulus (n) and exponent
 * (e), then hand it to OpenSSL for signature verification. Only RSA keys (kty=RSA) are
 * supported, which covers the RS256/384/512 algorithms used by essentially all major OIDC
 * providers (Entra ID, Google, Okta, Auth0, Keycloak, ...).
 *
 * @internal
 */
final class Jwk
{
    /**
     * Select the matching key from a JWKS "keys" array by `kid` (or the sole key if no kid),
     * and return it as a PEM public key.
     *
     * @param array<int,array<string,mixed>> $keys the "keys" array from a JWKS document
     */
    public static function toPemFromSet(array $keys, ?string $kid): string
    {
        $candidates = [];
        foreach ($keys as $key) {
            if (($key['kty'] ?? null) !== 'RSA') {
                continue;
            }
            if ($kid !== null && isset($key['kid']) && $key['kid'] !== $kid) {
                continue;
            }
            $candidates[] = $key;
        }
        if ($candidates === []) {
            throw new AuthenticationException('No matching RSA signing key (kid) found in JWKS.');
        }
        // If a kid was given, exactly one should match; otherwise use the first RSA key.
        return self::toPem($candidates[0]);
    }

    /**
     * Convert a single RSA JWK (with base64url n and e) into a PEM public key string.
     *
     * @param array<string,mixed> $jwk
     */
    public static function toPem(array $jwk): string
    {
        if (($jwk['kty'] ?? null) !== 'RSA' || !isset($jwk['n'], $jwk['e'])) {
            throw new AuthenticationException('Unsupported JWK: expected an RSA key with n and e.');
        }
        $n = self::b64uDecode((string) $jwk['n']);
        $e = self::b64uDecode((string) $jwk['e']);
        if ($n === '' || $e === '') {
            throw new AuthenticationException('Invalid RSA JWK: empty modulus or exponent.');
        }

        $rsaPublicKey = self::derSequence(
            self::derInteger($n) . self::derInteger($e)
        );

        // AlgorithmIdentifier: rsaEncryption OID (1.2.840.113549.1.1.1) + NULL params
        $rsaOid = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $spki = self::derSequence(
            $rsaOid . self::derBitString($rsaPublicKey)
        );

        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";

        return $pem;
    }

    private static function derInteger(string $bytes): string
    {
        // Strip leading zero bytes (keep at least one byte).
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }
        // If the high bit is set, prepend 0x00 so it is interpreted as positive.
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . self::derLength(strlen($bytes)) . $bytes;
    }

    private static function derBitString(string $bytes): string
    {
        // 0x00 = number of unused bits in the final byte.
        $content = "\x00" . $bytes;
        return "\x03" . self::derLength(strlen($content)) . $content;
    }

    private static function derSequence(string $content): string
    {
        return "\x30" . self::derLength(strlen($content)) . $content;
    }

    private static function derLength(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $out = '';
        while ($len > 0) {
            $out = chr($len & 0xff) . $out;
            $len >>= 8;
        }
        return chr(0x80 | strlen($out)) . $out;
    }

    private static function b64uDecode(string $s): string
    {
        $b64 = strtr($s, '-_', '+/');
        $pad = strlen($b64) % 4;
        if ($pad) {
            $b64 .= str_repeat('=', 4 - $pad);
        }
        $out = base64_decode($b64, true);
        return $out === false ? '' : $out;
    }
}
