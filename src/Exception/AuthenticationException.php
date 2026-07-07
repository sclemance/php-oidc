<?php

declare(strict_types=1);

namespace Sclemance\Oidc\Exception;

/**
 * Thrown when authentication fails: an error returned by the provider, a failed
 * token exchange, an invalid/failed token validation, or a rejected authorization
 * constraint (e.g. the user is authenticated but not permitted by your policy).
 *
 * The optional $oauthError carries the provider's `error` code (e.g. "login_required",
 * "access_denied", "consent_required") when present, which is useful for deciding how
 * to react to a failed silent (prompt=none) check.
 */
final class AuthenticationException extends OidcException
{
    public function __construct(
        string $message,
        public readonly ?string $oauthError = null,
        public readonly ?string $oauthErrorDescription = null,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, 0, $previous);
    }
}
