<?php

declare(strict_types=1);

namespace Sclemance\Oidc\Cache;

/**
 * Tiny cache abstraction used for provider discovery documents and JWKS.
 * Implement this to plug in your framework's cache (PSR-16, Redis, etc.).
 */
interface CacheInterface
{
    /** @return array<string,mixed>|null null if missing or expired */
    public function get(string $key): ?array;

    /** @param array<string,mixed> $value */
    public function set(string $key, array $value, int $ttlSeconds): void;
}
