<?php

declare(strict_types=1);

namespace Sclemance\Oidc\Session;

/**
 * Default session store backed by native PHP sessions. Values are namespaced under a single
 * $_SESSION key so this coexists with the host application's own session data.
 *
 * Starts a session on demand with sane cookie flags (HttpOnly, SameSite=Lax, Secure when the
 * request is HTTPS). If the host app already started a session, that one is reused.
 */
final class PhpSessionStore implements SessionStoreInterface
{
    public function __construct(private string $namespace = 'oidc')
    {
    }

    public function get(string $key): mixed
    {
        $this->start();
        return $_SESSION[$this->namespace][$key] ?? null;
    }

    public function set(string $key, mixed $value): void
    {
        $this->start();
        $_SESSION[$this->namespace][$key] = $value;
    }

    public function remove(string $key): void
    {
        $this->start();
        unset($_SESSION[$this->namespace][$key]);
    }

    public function regenerate(): void
    {
        $this->start();
        session_regenerate_id(true);
    }

    private function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        if (headers_sent()) {
            // Session cannot be started this late; assume the host already manages it.
            return;
        }
        session_start([
            'cookie_httponly' => true,
            'cookie_samesite' => 'Lax',
            'cookie_secure'   => $this->isHttps(),
        ]);
    }

    private function isHttps(): bool
    {
        return (($_SERVER['HTTPS'] ?? '') !== '' && ($_SERVER['HTTPS'] ?? '') !== 'off')
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
            || ((int) ($_SERVER['SERVER_PORT'] ?? 0) === 443);
    }
}
