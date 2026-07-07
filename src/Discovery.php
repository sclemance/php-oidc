<?php

declare(strict_types=1);

namespace Sclemance\Oidc;

use Sclemance\Oidc\Cache\CacheInterface;
use Sclemance\Oidc\Exception\OidcException;

/**
 * Fetches and caches the provider's OpenID Connect discovery document and JWKS.
 *
 * @internal
 */
final class Discovery
{
    /** @var array<string,mixed>|null */
    private ?array $doc = null;

    public function __construct(
        private string $discoveryUrl,
        private Http $http,
        private CacheInterface $cache,
        private int $ttl
    ) {
    }

    public function issuer(): string
    {
        return (string) $this->get('issuer');
    }

    public function authorizationEndpoint(): string
    {
        return (string) $this->get('authorization_endpoint');
    }

    public function tokenEndpoint(): string
    {
        return (string) $this->get('token_endpoint');
    }

    public function jwksUri(): string
    {
        return (string) $this->get('jwks_uri');
    }

    public function userinfoEndpoint(): ?string
    {
        $doc = $this->document();
        return isset($doc['userinfo_endpoint']) ? (string) $doc['userinfo_endpoint'] : null;
    }

    public function endSessionEndpoint(): ?string
    {
        $doc = $this->document();
        return isset($doc['end_session_endpoint']) ? (string) $doc['end_session_endpoint'] : null;
    }

    /**
     * Return the JWKS "keys" array, cached separately from the discovery document.
     *
     * @return array<int,array<string,mixed>>
     */
    public function jwksKeys(): array
    {
        $key = 'jwks:' . $this->jwksUri();
        $cached = $this->cache->get($key);
        if ($cached !== null && isset($cached['keys']) && is_array($cached['keys'])) {
            return $cached['keys'];
        }
        $jwks = $this->http->getJson($this->jwksUri());
        if (!isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new OidcException('JWKS document has no "keys" array.');
        }
        $this->cache->set($key, ['keys' => $jwks['keys']], $this->ttl);
        return $jwks['keys'];
    }

    /**
     * Force a JWKS refresh (used once if a token references an unknown kid — key rotation).
     *
     * @return array<int,array<string,mixed>>
     */
    public function refreshJwksKeys(): array
    {
        $this->cache->set('jwks:' . $this->jwksUri(), ['keys' => []], 0);
        return $this->jwksKeys();
    }

    private function get(string $field): mixed
    {
        $doc = $this->document();
        if (!isset($doc[$field])) {
            throw new OidcException("Discovery document missing '{$field}'.");
        }
        return $doc[$field];
    }

    /**
     * @return array<string,mixed>
     */
    private function document(): array
    {
        if ($this->doc !== null) {
            return $this->doc;
        }
        $cacheKey = 'disco:' . $this->discoveryUrl;
        $cached = $this->cache->get($cacheKey);
        if ($cached !== null) {
            return $this->doc = $cached;
        }
        $doc = $this->http->getJson($this->discoveryUrl);
        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $req) {
            if (!isset($doc[$req])) {
                throw new OidcException("Discovery document missing required '{$req}'.");
            }
        }
        $this->cache->set($cacheKey, $doc, $this->ttl);
        return $this->doc = $doc;
    }
}
