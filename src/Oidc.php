<?php

declare(strict_types=1);

namespace Sclemance\Oidc;

use Sclemance\Oidc\Exception\AuthenticationException;

/**
 * OpenID Connect client (Authorization Code flow + PKCE), framework-agnostic and
 * dependency-free.
 *
 * The headline method is requireAuth(): drop it at the top of any page and the visitor is
 * transparently authenticated — if they already have a session with the provider (SSO) they
 * bounce straight back with no clicks. Only truly-signed-out users ever see the provider's
 * login screen.
 *
 *     $oidc = new Oidc([
 *         'issuer'        => 'https://login.microsoftonline.com/<tenant-id>/v2.0',
 *         'client_id'     => '...',
 *         'client_secret' => '...',              // omit for a public client (PKCE only)
 *         'redirect_uri'  => 'https://app.example.com/callback.php',
 *     ]);
 *     $user = $oidc->requireAuth();
 *     echo 'Hello ' . htmlspecialchars($user->name() ?? $user->email() ?? $user->sub());
 *
 * See the examples/ directory for the one-file pattern and the dedicated-callback pattern.
 */
final class Oidc
{
    private const S_USER = 'user';
    private const S_TX   = 'tx';
    private const S_META = 'meta';

    private Config $config;
    private Http $http;
    private Discovery $discovery;

    /**
     * @param array<string,mixed>|Config $config
     */
    public function __construct(array|Config $config)
    {
        $this->config = $config instanceof Config ? $config : new Config($config);
        $this->http = new Http($this->config->httpTimeout);
        $this->discovery = new Discovery(
            $this->config->discoveryUrl,
            $this->http,
            $this->config->cache,
            $this->config->cacheTtl
        );
    }

    // ---- Public API -------------------------------------------------------------------

    /**
     * Ensure the visitor is authenticated, driving the redirect flow automatically as needed.
     *
     * - Already authenticated  -> returns the UserInfo immediately (no redirect).
     * - Arriving on a callback -> completes login and redirects to the originating URL (exits).
     * - Otherwise              -> redirects to the provider to authenticate (exits).
     *
     * Simple by default; extensible when you want it. To render your OWN failure page (bad
     * state, provider error, denied by your authorize policy), wrap the call:
     *
     *     try { $user = $oidc->requireAuth(); }
     *     catch (Sclemance\Oidc\Exception\AuthenticationException $e) {
     *         // $e->oauthError carries the provider's error code when present.
     *         http_response_code(403);
     *         require 'my-access-denied.php';
     *         exit;
     *     }
     *
     * For full control over the redirects themselves (no header()/exit from the library), use
     * the primitives instead: getAuthorizationUrl(), handleCallback(), user(), getLogoutUrl().
     *
     * @param array<string,string> $extraAuthParams e.g. ['prompt' => 'none'] for a silent check
     * @throws AuthenticationException on a failed/denied callback
     */
    public function requireAuth(array $extraAuthParams = []): UserInfo
    {
        $existing = $this->user();
        if ($existing !== null) {
            return $existing;
        }

        if ($this->isCallback()) {
            $returnTo = $this->pendingReturnTo();
            $user = $this->handleCallback();
            $this->redirect($returnTo);       // strip code/state from the URL, then re-enter
        }

        $this->login(null, $extraAuthParams); // redirects and exits
    }

    /**
     * Non-redirecting check. Returns the current user or null.
     *
     * Enforces the optional idle/absolute session timeouts: an expired session is cleared and
     * null is returned (so requireAuth() will transparently re-authenticate).
     */
    public function user(): ?UserInfo
    {
        $data = $this->config->session->get(self::S_USER);
        if (!is_array($data)) {
            return null;
        }

        $now = time();
        $meta = $this->config->session->get(self::S_META);
        $meta = is_array($meta) ? $meta : [];

        if ($this->config->absoluteTtl > 0
            && isset($meta['auth_time'])
            && $now - (int) $meta['auth_time'] > $this->config->absoluteTtl) {
            $this->forgetUser();
            return null;
        }
        if ($this->config->idleTtl > 0
            && isset($meta['last_seen'])
            && $now - (int) $meta['last_seen'] > $this->config->idleTtl) {
            $this->forgetUser();
            return null;
        }
        if ($this->config->idleTtl > 0) {
            $meta['last_seen'] = $now;
            $this->config->session->set(self::S_META, $meta);
        }

        return UserInfo::fromSession($data);
    }

    public function isAuthenticated(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Build the authorization-request URL and persist the login transaction — WITHOUT
     * redirecting. Use this if you want to control the redirect yourself (e.g. return a
     * framework redirect response, or show an interstitial). Otherwise use login().
     *
     * @param array<string,string> $extraAuthParams
     */
    public function getAuthorizationUrl(?string $returnTo = null, array $extraAuthParams = []): string
    {
        $returnTo ??= $this->currentUrl();

        $state = self::randomToken();
        $nonce = self::randomToken();
        $verifier = $this->config->pkce ? self::randomToken(64) : null;

        $this->config->session->set(self::S_TX, [
            'state'    => $state,
            'nonce'    => $nonce,
            'verifier' => $verifier,
            'return'   => $returnTo,
            'ts'       => time(),
        ]);

        $params = [
            'response_type' => 'code',
            'client_id'     => $this->config->clientId,
            'redirect_uri'  => $this->config->redirectUri,
            'scope'         => implode(' ', $this->config->scopes),
            'state'         => $state,
            'nonce'         => $nonce,
        ];
        if ($verifier !== null) {
            $params['code_challenge'] = self::b64u(hash('sha256', $verifier, true));
            $params['code_challenge_method'] = 'S256';
        }
        $params += $this->config->authParams;
        $params = array_merge($params, $extraAuthParams);

        return $this->discovery->authorizationEndpoint() . '?' . http_build_query($params);
    }

    /**
     * Begin authentication explicitly (e.g. from a "Sign in" button). Redirects and exits.
     *
     * @param array<string,string> $extraAuthParams
     */
    public function login(?string $returnTo = null, array $extraAuthParams = []): never
    {
        $this->redirect($this->getAuthorizationUrl($returnTo, $extraAuthParams));
    }

    /**
     * Complete the flow at the redirect URI: validate state, exchange the code, validate the
     * ID token, apply any authorization policy, and establish the session. Returns the user.
     *
     * Use this directly on a dedicated callback endpoint; requireAuth() calls it for you when
     * it detects a callback.
     */
    public function handleCallback(): UserInfo
    {
        $tx = $this->config->session->get(self::S_TX);
        if (!is_array($tx) || empty($tx['state'])) {
            throw new AuthenticationException('No login transaction in progress (missing state).');
        }

        $qsState = isset($_GET['state']) ? (string) $_GET['state'] : '';
        if ($qsState === '' || !hash_equals((string) $tx['state'], $qsState)) {
            throw new AuthenticationException('State mismatch (possible CSRF).');
        }

        // Provider-side error (also how prompt=none reports "not signed in").
        if (isset($_GET['error'])) {
            $this->config->session->remove(self::S_TX);
            throw new AuthenticationException(
                'Authorization request was rejected by the provider.',
                (string) $_GET['error'],
                isset($_GET['error_description']) ? (string) $_GET['error_description'] : null
            );
        }

        $code = isset($_GET['code']) ? (string) $_GET['code'] : '';
        if ($code === '') {
            throw new AuthenticationException('Missing authorization code.');
        }

        $tokens = $this->exchangeCode($code, $tx['verifier'] ?? null);
        $claims = $this->validateIdToken((string) ($tokens['id_token'] ?? ''), $tx['nonce'] ?? null);

        if ($this->config->authorize !== null && !($this->config->authorize)($claims)) {
            $this->config->session->remove(self::S_TX);
            throw new AuthenticationException('Authenticated, but not permitted by authorization policy.');
        }

        $user = new UserInfo($claims, $tokens);

        // New authenticated session: rotate the id, then store.
        $this->config->session->regenerate();
        $sessionData = $user->toSession();
        if (!$this->config->storeTokens) {
            // Keep claims but do not persist tokens (they remain available on the returned
            // UserInfo for use during THIS request).
            $sessionData['tokens'] = [];
        }
        $this->config->session->set(self::S_USER, $sessionData);
        $now = time();
        $this->config->session->set(self::S_META, ['auth_time' => $now, 'last_seen' => $now]);
        $this->config->session->remove(self::S_TX);

        return $user;
    }

    /** Clear the local session only (no redirect). */
    public function forgetUser(): void
    {
        $this->config->session->remove(self::S_USER);
        $this->config->session->remove(self::S_META);
        $this->config->session->remove(self::S_TX);
        $this->config->session->regenerate();
    }

    /**
     * Build the provider's RP-initiated logout (end-session) URL, or null if the provider
     * doesn't advertise one. Does NOT clear the session or redirect — call forgetUser()
     * yourself if you use this primitive.
     */
    public function getLogoutUrl(?string $returnTo = null, ?string $idTokenHint = null): ?string
    {
        $endpoint = $this->discovery->endSessionEndpoint();
        if ($endpoint === null) {
            return null;
        }
        $params = [];
        if ($idTokenHint !== null) {
            $params['id_token_hint'] = $idTokenHint;
        }
        $post = $returnTo ?? $this->config->postLogoutRedirectUri;
        if ($post !== null) {
            $params['post_logout_redirect_uri'] = $post;
        }
        return $endpoint . ($params ? '?' . http_build_query($params) : '');
    }

    /**
     * Log out locally, and (if the provider supports it) redirect to the provider's
     * end-session endpoint for a full single-logout. If no provider logout is available or
     * $providerLogout is false, redirects to $returnTo (or returns if it is null).
     */
    public function logout(?string $returnTo = null, bool $providerLogout = true): void
    {
        $idToken = $this->user()?->idToken();
        $this->forgetUser();

        $post = $returnTo ?? $this->config->postLogoutRedirectUri;

        if ($providerLogout) {
            $url = $this->getLogoutUrl($post, $idToken);
            if ($url !== null) {
                $this->redirect($url);
            }
        }
        if ($post !== null) {
            $this->redirect($post);
        }
    }

    /**
     * Optionally enrich the profile from the UserInfo endpoint using the access token.
     * Returns merged claims (does not persist). Useful when the ID token is sparse.
     *
     * @return array<string,mixed>
     */
    public function fetchUserInfo(UserInfo $user): array
    {
        $endpoint = $this->discovery->userinfoEndpoint();
        $token = $user->accessToken();
        if ($endpoint === null || $token === null) {
            return $user->claims();
        }
        $info = $this->httpGetWithBearer($endpoint, $token);
        return array_merge($user->claims(), $info);
    }

    // ---- Internals --------------------------------------------------------------------

    /**
     * @param string|null $verifier
     * @return array<string,mixed>
     */
    private function exchangeCode(string $code, ?string $verifier): array
    {
        $fields = [
            'grant_type'   => 'authorization_code',
            'code'         => $code,
            'redirect_uri' => $this->config->redirectUri,
            'client_id'    => $this->config->clientId,
        ];
        if ($this->config->clientSecret !== null) {
            $fields['client_secret'] = $this->config->clientSecret;
        }
        if ($verifier !== null) {
            $fields['code_verifier'] = $verifier;
        }

        $resp = $this->http->postForm($this->discovery->tokenEndpoint(), $fields);
        $body = $resp['body'];
        if ($resp['status'] < 200 || $resp['status'] >= 300 || isset($body['error'])) {
            $err = isset($body['error']) ? (string) $body['error'] : ('HTTP ' . $resp['status']);
            $desc = isset($body['error_description']) ? (string) $body['error_description'] : null;
            throw new AuthenticationException("Token exchange failed: {$err}", $err, $desc);
        }
        if (empty($body['id_token'])) {
            throw new AuthenticationException('Token response did not include an id_token.');
        }
        return $body;
    }

    /**
     * @return array<string,mixed> validated claims
     */
    private function validateIdToken(string $idToken, ?string $expectedNonce): array
    {
        $parsed = Jwt::parse($idToken);

        if ($this->config->verifySignature) {
            $kid = isset($parsed['header']['kid']) ? (string) $parsed['header']['kid'] : null;
            $pem = $this->resolveSigningKey($kid);
            Jwt::verifySignature($parsed['header'], $parsed['signingInput'], $parsed['signature'], $pem);
        }

        $issuer = $this->config->issuerOverride ?? $this->discovery->issuer();
        Jwt::validateClaims(
            $parsed['payload'],
            $issuer,
            $this->config->clientId,
            $expectedNonce !== null ? (string) $expectedNonce : null,
            $this->config->leeway
        );

        return $parsed['payload'];
    }

    private function resolveSigningKey(?string $kid): string
    {
        try {
            return Jwk::toPemFromSet($this->discovery->jwksKeys(), $kid);
        } catch (AuthenticationException $e) {
            // Key may have rotated since we cached the JWKS; refresh once and retry.
            return Jwk::toPemFromSet($this->discovery->refreshJwksKeys(), $kid);
        }
    }

    private function isCallback(): bool
    {
        if (!isset($_GET['state'])) {
            return false;
        }
        $tx = $this->config->session->get(self::S_TX);
        if (!is_array($tx) || empty($tx['state'])) {
            return false;
        }
        if (!hash_equals((string) $tx['state'], (string) $_GET['state'])) {
            return false;
        }
        return isset($_GET['code']) || isset($_GET['error']);
    }

    private function pendingReturnTo(): string
    {
        $tx = $this->config->session->get(self::S_TX);
        return is_array($tx) && !empty($tx['return']) ? (string) $tx['return'] : '/';
    }

    /**
     * @return array<string,mixed>
     */
    private function httpGetWithBearer(string $url, string $bearer): array
    {
        // One-off GET with a bearer header (the UserInfo endpoint). Uses streams directly to
        // keep Http's public surface minimal.
        $context = stream_context_create([
            'http' => ['method' => 'GET', 'header' => 'Authorization: Bearer ' . $bearer, 'ignore_errors' => true, 'timeout' => $this->config->httpTimeout],
            'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);
        $raw = @file_get_contents($url, false, $context);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        return is_array($data) ? $data : [];
    }

    private function currentUrl(): string
    {
        $https = (($_SERVER['HTTPS'] ?? '') !== '' && ($_SERVER['HTTPS'] ?? '') !== 'off')
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
        $scheme = $https ? 'https' : 'http';
        $host = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        return $scheme . '://' . $host . $uri;
    }

    private function redirect(string $url): never
    {
        header('Location: ' . $url, true, 302);
        exit;
    }

    private static function randomToken(int $bytes = 32): string
    {
        return self::b64u(random_bytes($bytes));
    }

    private static function b64u(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }
}
