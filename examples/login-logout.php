<?php
/**
 * Button-driven pattern: don't force login on arrival, show a "Sign in" button instead.
 *
 * Handy for public pages that have an optional account area. requireAuth() is the automatic
 * path; login()/logout() are the explicit ones.
 */

require __DIR__ . '/bootstrap.php';

$action = $_GET['do'] ?? '';

if ($action === 'login') {
    oidc()->login('/login-logout.php');    // redirects to the provider, returns here after
}
if ($action === 'logout') {
    oidc()->logout('/login-logout.php');   // clears the session (+ provider logout if available)
}

$user = oidc()->user();  // non-redirecting: null when signed out
?>
<!doctype html>
<title>Account</title>
<?php if ($user): ?>
    <p>Signed in as <strong><?= htmlspecialchars($user->email() ?? $user->sub(), ENT_QUOTES) ?></strong>.</p>
    <p><a href="?do=logout">Sign out</a></p>
<?php else: ?>
    <p>You are not signed in.</p>
    <p><a href="?do=login">Sign in with your organization account</a></p>
<?php endif; ?>
