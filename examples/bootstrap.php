<?php
/**
 * Shared configuration used by the "dedicated callback" example files
 * (callback.php, login-logout.php, and any protected page).
 *
 * In a real app, load these values from a config file kept OUTSIDE the web root or from
 * environment variables — never hard-code secrets in a web-served file.
 */

require __DIR__ . '/../autoload.php';

use Sclemance\Oidc\Oidc;

function oidc(): Oidc
{
    static $oidc = null;
    if ($oidc === null) {
        $oidc = new Oidc([
            'issuer'        => getenv('OIDC_ISSUER')        ?: 'https://login.microsoftonline.com/<tenant-id>/v2.0',
            'client_id'     => getenv('OIDC_CLIENT_ID')     ?: '<client-id>',
            'client_secret' => getenv('OIDC_CLIENT_SECRET') ?: '<client-secret>',
            'redirect_uri'  => getenv('OIDC_REDIRECT_URI')  ?: 'https://app.example.com/callback.php',
        ]);
    }
    return $oidc;
}
