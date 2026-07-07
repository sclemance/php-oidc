<?php

declare(strict_types=1);

namespace Sclemance\Oidc;

use Sclemance\Oidc\Cache\CacheInterface;
use Sclemance\Oidc\Cache\FileCache;
use Sclemance\Oidc\Exception\ConfigException;
use Sclemance\Oidc\Session\PhpSessionStore;
use Sclemance\Oidc\Session\SessionStoreInterface;

/**
 * Validated, normalized configuration for the Oidc client.
 */
final class Config
{
    /** @var string[] */
    public readonly array $scopes;
    public readonly string $discoveryUrl;
    public readonly ?string $issuerOverride;
    public readonly string $clientId;
    public readonly ?string $clientSecret;
    public readonly string $redirectUri;
    public readonly bool $pkce;
    public readonly bool $verifySignature;
    public readonly int $leeway;
    public readonly int $cacheTtl;
    public readonly int $httpTimeout;
    public readonly bool $storeTokens;
    public readonly int $idleTtl;      // seconds; 0 = disabled
    public readonly int $absoluteTtl;  // seconds; 0 = disabled
    public readonly ?string $postLogoutRedirectUri;
    public readonly string $sessionNamespace;
    /** @var array<string,string> extra params added to the authorization request */
    public readonly array $authParams;
    /** @var callable|null (array $claims): bool — return false to deny an authenticated user */
    public $authorize;
    public readonly SessionStoreInterface $session;
    public readonly CacheInterface $cache;

    /**
     * @param array<string,mixed> $c
     */
    public function __construct(array $c)
    {
        $this->clientId = self::str($c, 'client_id', true);
        $this->redirectUri = self::str($c, 'redirect_uri', true);
        $this->clientSecret = isset($c['client_secret']) && $c['client_secret'] !== ''
            ? (string) $c['client_secret'] : null;

        // Either an issuer (from which the discovery URL is derived) or an explicit discovery_url.
        $issuer = isset($c['issuer']) ? rtrim((string) $c['issuer'], '/') : '';
        $discovery = isset($c['discovery_url']) ? (string) $c['discovery_url'] : '';
        if ($discovery === '' && $issuer === '') {
            throw new ConfigException("Provide 'issuer' (recommended) or 'discovery_url'.");
        }
        $this->discoveryUrl = $discovery !== ''
            ? $discovery
            : $issuer . '/.well-known/openid-configuration';
        // If the caller supplied an explicit issuer, we validate id_token 'iss' against it.
        $this->issuerOverride = $issuer !== '' ? $issuer : (isset($c['expected_issuer']) ? (string) $c['expected_issuer'] : null);

        $scopes = $c['scopes'] ?? ['openid', 'profile', 'email'];
        if (is_string($scopes)) {
            $scopes = preg_split('/\s+/', trim($scopes)) ?: [];
        }
        $scopes = array_values(array_unique(array_filter(array_map('strval', (array) $scopes))));
        if (!in_array('openid', $scopes, true)) {
            array_unshift($scopes, 'openid');
        }
        $this->scopes = $scopes;

        $this->pkce = (bool) ($c['pkce'] ?? true);
        $this->verifySignature = (bool) ($c['verify_signature'] ?? true);
        $this->leeway = (int) ($c['leeway'] ?? 60);
        $this->cacheTtl = (int) ($c['cache_ttl'] ?? 3600);
        $this->httpTimeout = (int) ($c['http_timeout'] ?? 15);

        // Opt-in session hardening. All default to "off" so the simple case is unchanged.
        $this->storeTokens = (bool) ($c['store_tokens'] ?? true);
        $this->idleTtl = max(0, (int) ($c['session_idle_ttl'] ?? 0));
        $this->absoluteTtl = max(0, (int) ($c['session_absolute_ttl'] ?? 0));
        $this->postLogoutRedirectUri = isset($c['post_logout_redirect_uri'])
            ? (string) $c['post_logout_redirect_uri'] : null;
        $this->sessionNamespace = (string) ($c['session_namespace'] ?? 'oidc');

        $authParams = $c['auth_params'] ?? [];
        $this->authParams = is_array($authParams)
            ? array_map('strval', $authParams) : [];

        if (isset($c['authorize'])) {
            if (!is_callable($c['authorize'])) {
                throw new ConfigException("'authorize' must be callable.");
            }
            $this->authorize = $c['authorize'];
        } else {
            $this->authorize = null;
        }

        $session = $c['session'] ?? null;
        if ($session !== null && !$session instanceof SessionStoreInterface) {
            throw new ConfigException("'session' must implement SessionStoreInterface.");
        }
        $this->session = $session ?? new PhpSessionStore($this->sessionNamespace);

        $cache = $c['cache'] ?? null;
        if ($cache !== null && !$cache instanceof CacheInterface) {
            throw new ConfigException("'cache' must implement CacheInterface.");
        }
        $this->cache = $cache ?? new FileCache();
    }

    /**
     * @param array<string,mixed> $c
     */
    private static function str(array $c, string $key, bool $required): string
    {
        $val = isset($c[$key]) ? (string) $c[$key] : '';
        if ($required && $val === '') {
            throw new ConfigException("Missing required config: '{$key}'.");
        }
        return $val;
    }
}
