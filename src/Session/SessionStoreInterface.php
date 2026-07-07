<?php

declare(strict_types=1);

namespace Sclemance\Oidc\Session;

/**
 * Storage for both the authenticated session and the short-lived transaction state
 * (state/nonce/PKCE verifier/return URL) used during the redirect round-trip.
 *
 * The default PhpSessionStore uses native PHP sessions. Implement this to integrate with a
 * framework's session (Laravel, Symfony, etc.) or a custom store.
 */
interface SessionStoreInterface
{
    public function get(string $key): mixed;

    public function set(string $key, mixed $value): void;

    public function remove(string $key): void;

    /** Mitigate session fixation after a successful login. */
    public function regenerate(): void;
}
