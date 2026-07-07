<?php

declare(strict_types=1);

namespace Sclemance\Oidc;

/**
 * The authenticated user: validated ID-token claims plus the tokens obtained during login.
 *
 * Convenience accessors cover the common claims; use claim() / claims() for anything else
 * (e.g. 'oid', 'preferred_username', 'groups', 'roles').
 */
final class UserInfo implements \JsonSerializable
{
    /**
     * @param array<string,mixed> $claims validated ID-token claims
     * @param array<string,mixed> $tokens raw token endpoint response (id_token, access_token, ...)
     */
    public function __construct(
        private array $claims,
        private array $tokens = []
    ) {
    }

    public function sub(): string
    {
        return (string) ($this->claims['sub'] ?? '');
    }

    public function email(): ?string
    {
        $e = $this->claims['email'] ?? $this->claims['preferred_username'] ?? null;
        return $e !== null ? (string) $e : null;
    }

    public function name(): ?string
    {
        return isset($this->claims['name']) ? (string) $this->claims['name'] : null;
    }

    public function claim(string $key, mixed $default = null): mixed
    {
        return $this->claims[$key] ?? $default;
    }

    /** @return array<string,mixed> */
    public function claims(): array
    {
        return $this->claims;
    }

    public function idToken(): ?string
    {
        return isset($this->tokens['id_token']) ? (string) $this->tokens['id_token'] : null;
    }

    public function accessToken(): ?string
    {
        return isset($this->tokens['access_token']) ? (string) $this->tokens['access_token'] : null;
    }

    public function refreshToken(): ?string
    {
        return isset($this->tokens['refresh_token']) ? (string) $this->tokens['refresh_token'] : null;
    }

    /**
     * Rebuild from the array stored in the session.
     *
     * @param array<string,mixed> $data
     */
    public static function fromSession(array $data): self
    {
        return new self(
            is_array($data['claims'] ?? null) ? $data['claims'] : [],
            is_array($data['tokens'] ?? null) ? $data['tokens'] : []
        );
    }

    /**
     * The array persisted in the session. Note: this includes tokens; keep your session
     * store server-side (the default PHP session store is).
     *
     * @return array<string,mixed>
     */
    public function toSession(): array
    {
        return ['claims' => $this->claims, 'tokens' => $this->tokens];
    }

    /**
     * @return array<string,mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->claims;
    }
}
