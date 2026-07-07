<?php

declare(strict_types=1);

namespace Sclemance\Oidc;

use Sclemance\Oidc\Exception\AuthenticationException;

/**
 * ID token (JWT) parsing, signature verification, and claim validation.
 *
 * @internal
 */
final class Jwt
{
    private const ALG_TO_OPENSSL = [
        'RS256' => OPENSSL_ALGO_SHA256,
        'RS384' => OPENSSL_ALGO_SHA384,
        'RS512' => OPENSSL_ALGO_SHA512,
    ];

    /**
     * Split and decode a compact JWS without verifying it.
     *
     * @return array{header:array<string,mixed>, payload:array<string,mixed>, signingInput:string, signature:string}
     */
    public static function parse(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new AuthenticationException('Malformed JWT: expected three segments.');
        }
        [$h, $p, $s] = $parts;
        $header  = json_decode(self::b64uDecode($h), true);
        $payload = json_decode(self::b64uDecode($p), true);
        if (!is_array($header) || !is_array($payload)) {
            throw new AuthenticationException('Malformed JWT: invalid header or payload JSON.');
        }
        return [
            'header'       => $header,
            'payload'      => $payload,
            'signingInput' => $h . '.' . $p,
            'signature'    => self::b64uDecode($s),
        ];
    }

    /**
     * Verify an RSA signature over the JWT signing input using a PEM public key.
     * The algorithm is taken from the (already-parsed) header and constrained to RS256/384/512.
     *
     * @param array<string,mixed> $header
     */
    public static function verifySignature(array $header, string $signingInput, string $signature, string $pem): void
    {
        $alg = (string) ($header['alg'] ?? '');
        if (!isset(self::ALG_TO_OPENSSL[$alg])) {
            throw new AuthenticationException("Unsupported or missing JWT alg: '{$alg}'. Expected RS256/RS384/RS512.");
        }
        $ok = openssl_verify($signingInput, $signature, $pem, self::ALG_TO_OPENSSL[$alg]);
        if ($ok !== 1) {
            throw new AuthenticationException('ID token signature verification failed.');
        }
    }

    /**
     * Validate the standard OIDC claims.
     *
     * @param array<string,mixed> $claims
     */
    public static function validateClaims(
        array $claims,
        string $issuer,
        string $clientId,
        ?string $expectedNonce,
        int $leeway
    ): void {
        $now = time();

        if (($claims['iss'] ?? null) !== $issuer) {
            throw new AuthenticationException('ID token issuer (iss) mismatch.');
        }

        // aud may be a string or an array; it must contain the client_id.
        $aud = $claims['aud'] ?? null;
        $audList = is_array($aud) ? $aud : [$aud];
        if (!in_array($clientId, $audList, true)) {
            throw new AuthenticationException('ID token audience (aud) does not include this client.');
        }

        // When multiple audiences are present, azp (authorized party) must be this client.
        if (is_array($aud) && count($aud) > 1 && ($claims['azp'] ?? $clientId) !== $clientId) {
            throw new AuthenticationException('ID token azp mismatch for multi-audience token.');
        }

        if (!isset($claims['exp']) || $now >= ((int) $claims['exp'] + $leeway)) {
            throw new AuthenticationException('ID token is expired.');
        }
        if (isset($claims['nbf']) && $now < ((int) $claims['nbf'] - $leeway)) {
            throw new AuthenticationException('ID token is not yet valid (nbf).');
        }
        if (isset($claims['iat']) && $now < ((int) $claims['iat'] - $leeway)) {
            throw new AuthenticationException('ID token issued-at (iat) is in the future.');
        }

        if ($expectedNonce !== null) {
            $tokenNonce = isset($claims['nonce']) ? (string) $claims['nonce'] : '';
            if ($tokenNonce === '' || !hash_equals($expectedNonce, $tokenNonce)) {
                throw new AuthenticationException('ID token nonce mismatch (possible replay).');
            }
        }
    }

    public static function b64uDecode(string $s): string
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
