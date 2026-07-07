<?php
/**
 * Minimal logout endpoint for the protect-page.php example.
 */
require __DIR__ . '/../autoload.php';

use Sclemance\Oidc\Oidc;

$oidc = new Oidc([
    'issuer'                    => 'https://login.microsoftonline.com/<tenant-id>/v2.0',
    'client_id'                 => '<client-id>',
    'client_secret'             => '<client-secret>',
    'redirect_uri'              => 'https://app.example.com/protect-page.php',
    'post_logout_redirect_uri'  => 'https://app.example.com/protect-page.php',
]);

$oidc->logout();  // local logout + provider single-logout, then back to the post-logout URL
