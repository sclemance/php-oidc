<?php

declare(strict_types=1);

namespace Sclemance\Oidc\Cache;

/**
 * Default filesystem cache for discovery/JWKS documents. Stores JSON files in a directory
 * (defaults to the system temp dir). Safe to share across processes; writes are atomic.
 */
final class FileCache implements CacheInterface
{
    private string $dir;

    public function __construct(?string $dir = null)
    {
        $this->dir = rtrim($dir ?? (sys_get_temp_dir() . '/php-oidc-cache'), '/');
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0700, true);
        }
    }

    public function get(string $key): ?array
    {
        $path = $this->path($key);
        if (!is_file($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        if ($raw === false) {
            return null;
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || !isset($data['expires'], $data['value'])) {
            return null;
        }
        if (time() >= (int) $data['expires']) {
            @unlink($path);
            return null;
        }
        return is_array($data['value']) ? $data['value'] : null;
    }

    public function set(string $key, array $value, int $ttlSeconds): void
    {
        $payload = json_encode(['expires' => time() + max(1, $ttlSeconds), 'value' => $value]);
        if ($payload === false) {
            return;
        }
        $path = $this->path($key);
        $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, $payload, LOCK_EX) !== false) {
            @rename($tmp, $path);
        }
    }

    private function path(string $key): string
    {
        return $this->dir . '/' . hash('sha256', $key) . '.json';
    }
}
