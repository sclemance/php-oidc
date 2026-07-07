<?php
/**
 * Simplest pattern: one file protects itself.
 *
 * Point your Entra/OIDC "redirect URI" at THIS page's URL. requireAuth() both starts the
 * login (when needed) and handles the callback when the provider redirects back here — so a
 * signed-in user sees zero prompts (SSO bounces straight through).
 *
 * Non-Composer: require the bundled autoloader. With Composer, require 'vendor/autoload.php'.
 */

require __DIR__ . '/../autoload.php';

use Sclemance\Oidc\Oidc;

$oidc = new Oidc([
    'issuer'        => 'https://login.microsoftonline.com/<tenant-id>/v2.0',
    'client_id'     => '<client-id>',
    'client_secret' => '<client-secret>',            // omit for a public client (PKCE only)
    'redirect_uri'  => 'https://app.example.com/protect-page.php',
    // Optional: restrict who may sign in (runs after authentication).
    'authorize'     => fn(array $claims) => str_ends_with((string)($claims['email'] ?? ''), '@example.com'),
]);

$user = $oidc->requireAuth();   // <- everything below only runs for authenticated users

$name = htmlspecialchars($user->name() ?? $user->email() ?? $user->sub(), ENT_QUOTES);
?>
<!doctype html>
<title>Protected</title>
<h1>Hello, <?= $name ?></h1>
<p>You are signed in via OpenID Connect.</p>
<p><a href="logout.php">Sign out</a></p>
