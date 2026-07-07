<?php
/**
 * Dedicated callback endpoint (register THIS url as the redirect URI).
 *
 * Use this pattern when you want one shared callback for the whole app and to protect many
 * pages. Protected pages call oidc()->requireAuth(); the provider always returns here, we
 * complete the login, then bounce the user back to wherever they started.
 */

require __DIR__ . '/bootstrap.php';

use Sclemance\Oidc\Exception\AuthenticationException;

try {
    oidc()->handleCallback();
    // handleCallback stored the session; send the user back to their original page.
    // (requireAuth() remembered it under the transaction; here we just default to home.)
    header('Location: /');
    exit;
} catch (AuthenticationException $e) {
    http_response_code(403);
    // For prompt=none silent checks, inspect $e->oauthError (e.g. 'login_required').
    echo 'Sign-in failed: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES);
}
