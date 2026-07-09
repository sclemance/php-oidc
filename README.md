# php-oidc

A small, **zero-dependency, framework-agnostic** OpenID Connect (OIDC) library for PHP.
Drop-in authentication with a single auto-checking call — no user clicks unless you want a button.

```php
use Sclemance\Oidc\Oidc;

$oidc = new Oidc([
    'issuer'        => 'https://login.microsoftonline.com/<tenant-id>/v2.0',
    'client_id'     => '<client-id>',
    'client_secret' => '<client-secret>',
    'redirect_uri'  => 'https://app.example.com/callback.php',
]);

$user = $oidc->requireAuth();          // signed-in users pass straight through (SSO, no clicks)
echo 'Hello ' . htmlspecialchars($user->name() ?? $user->email());
```

## Why

Most OIDC libraries make you wire up routes, sessions, token validation, and a callback
controller before anything works. `php-oidc` collapses that to one call: **`requireAuth()`**
handles the redirect *out* to the provider, the callback *back*, ID-token validation, and the
session — so a page is protected in one line. Works with any standards-compliant provider:
**Microsoft Entra ID (Azure AD), Google, Okta, Auth0, Keycloak, Ping**, and others.

## Features

- **Authorization Code flow + PKCE** (S256), the current best practice.
- **Automatic**: `requireAuth()` needs no user interaction; silent SSO just works. Add a
  button only if your app wants one (`login()` / `logout()`).
- **Full ID-token validation**: RS256/384/512 signature via JWKS, plus `iss`/`aud`/`exp`/`nbf`/
  `nonce` checks and a CSRF `state` check.
- **Zero runtime dependencies** — only `ext-openssl` + `ext-json`. No Composer required
  (a plain `autoload.php` is included). `ext-curl` optional; falls back to PHP streams.
- **Discovery + JWKS caching** (pluggable; file cache by default).
- **Pluggable session & cache** (implement an interface to use your framework's).
- **Authorization policy hook** to restrict *who* may sign in (domain, group, roles…).
- **Provider single-logout** (RP-initiated) when the provider supports it.

## Requirements

- PHP **8.1+**
- `ext-openssl`, `ext-json`
- Either `allow_url_fopen` enabled (default) **or** `ext-curl`

## Install

### With Composer (recommended)
```bash
composer require sclemance/php-oidc
```
```php
require 'vendor/autoload.php';
```

### Without Composer
Copy the repo somewhere and require the bundled autoloader:
```php
require '/path/to/php-oidc/autoload.php';
```

## Usage patterns

### 1. One file protects itself (simplest)
Register the page's own URL as the redirect URI. See `examples/protect-page.php`.
```php
$user = $oidc->requireAuth();   // starts login AND handles the callback on this same URL
```

### 2. Dedicated callback (protect many pages)
Register one `callback.php` as the redirect URI. Protected pages call `requireAuth()`; the
provider always returns to `callback.php`, which finishes login and bounces the user back.
See `examples/callback.php` + `examples/bootstrap.php`.

### 3. Optional login button
Don't force login on arrival — show a button. See `examples/login-logout.php`.
```php
if ($_GET['do'] ?? '' === 'login')  $oidc->login('/account.php');
if ($_GET['do'] ?? '' === 'logout') $oidc->logout('/');
$user = $oidc->user();   // null when signed out (never redirects)
```

### Silent check (no prompt)
Attempt SSO without ever showing a login screen; decide yourself what to do if there's no
session:
```php
// On a protected page, trigger a one-time silent attempt:
$oidc->login($returnTo, ['prompt' => 'none']);
// In your callback, a failed silent attempt arrives as an OAuth error:
try { $oidc->handleCallback(); }
catch (Sclemance\Oidc\Exception\AuthenticationException $e) {
    if ($e->oauthError === 'login_required') { /* show public page or a Sign-in button */ }
}
```

### Restrict who may sign in
`authorize` runs after authentication; return `false` to deny (throws `AuthenticationException`):
```php
'authorize' => fn(array $claims) =>
    str_ends_with($claims['email'] ?? '', '@example.com'),           // domain allow-list
    // or: in_array('<group-object-id>', $claims['groups'] ?? [], true),
```

## Simple by default, extensible when you need it

The one-liner covers most apps, but nothing is hidden from you.

**Render your own failure page.** `requireAuth()` throws `AuthenticationException` for a bad
`state`, a provider error, or a rejected `authorize` policy — catch it and show whatever you
want:
```php
use Sclemance\Oidc\Exception\AuthenticationException;

try {
    $user = $oidc->requireAuth();
} catch (AuthenticationException $e) {
    http_response_code(403);
    // $e->oauthError holds the provider's error code (e.g. 'access_denied') when present.
    require __DIR__ . '/views/access-denied.php';
    exit;
}
```

**Control the redirects yourself** (no `header()`/`exit` from the library) using the
primitives — handy inside a framework or when you want an interstitial:
```php
$url  = $oidc->getAuthorizationUrl($returnTo);   // build URL + stash transaction; you redirect
$user = $oidc->handleCallback();                 // exchange + validate at your callback route
$user = $oidc->user();                           // current user or null (no redirect)
$url  = $oidc->getLogoutUrl($returnTo, $idHint); // provider end-session URL (or null); you redirect
$oidc->forgetUser();                             // clear the local session only
```

**Harden the session** for sensitive apps (all opt-in):
```php
'store_tokens'         => false,   // don't persist tokens if you don't need them post-login
'session_idle_ttl'     => 1800,    // re-auth after 30 min idle
'session_absolute_ttl' => 28800,   // re-auth 8 h after login regardless of activity
```

> **Note (by design):** auth is session-based — there's no back-channel logout or live
> revocation check, so a local session stays valid until it (or a timeout) expires. Pair a
> timeout with your provider's Conditional Access for tighter control.

## Configuration reference

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `issuer` | yes* | — | Provider issuer URL; discovery is derived as `<issuer>/.well-known/openid-configuration`. |
| `discovery_url` | yes* | — | Explicit discovery URL (alternative to `issuer`). |
| `client_id` | yes | — | Application/client ID. |
| `client_secret` | no | — | Client secret. Omit for a public client (PKCE only). |
| `redirect_uri` | yes | — | Must exactly match a redirect URI registered with the provider. |
| `scopes` | no | `['openid','profile','email']` | Array or space-separated string; `openid` is always included. |
| `pkce` | no | `true` | Use PKCE S256. |
| `verify_signature` | no | `true` | Verify the ID-token signature against JWKS. |
| `leeway` | no | `60` | Clock-skew tolerance (seconds) for time-based claims. |
| `store_tokens` | no | `true` | Persist the access/refresh/ID tokens in the session. Set `false` to keep only claims (smaller attack surface); tokens are still returned by `handleCallback()`/`requireAuth()` for use during that request. |
| `session_idle_ttl` | no | `0` (off) | Re-authenticate after this many seconds of inactivity. |
| `session_absolute_ttl` | no | `0` (off) | Re-authenticate this many seconds after login, regardless of activity. |
| `authorize` | no | — | `callable(array $claims): bool` — return false to deny. |
| `auth_params` | no | `[]` | Extra authorization-request params (e.g. `['domain_hint'=>'acme.com']`). |
| `post_logout_redirect_uri` | no | — | Where the provider returns after single-logout. |
| `session` | no | `PhpSessionStore` | A `SessionStoreInterface` implementation. |
| `cache` | no | `FileCache` | A `CacheInterface` for discovery/JWKS. |
| `cache_ttl` | no | `3600` | Discovery/JWKS cache lifetime (seconds). |

\* Provide **either** `issuer` or `discovery_url`.

## Provider quick-config

```php
// Microsoft Entra ID (single tenant)
'issuer' => 'https://login.microsoftonline.com/<tenant-id>/v2.0',

// Google
'issuer' => 'https://accounts.google.com',

// Okta
'issuer' => 'https://<your-domain>.okta.com',

// Auth0
'issuer' => 'https://<your-tenant>.us.auth0.com/',

// Keycloak
'issuer' => 'https://<host>/realms/<realm>',
```

---

## Provisioning Microsoft Entra ID (July 2026)

You need an **app registration** with a redirect URI and a client secret. Pick the automated
script (fastest) or the portal steps.

### Option A — PowerShell script (recommended)

A ready-to-run script using the current **Microsoft Graph PowerShell SDK** is included at
[`scripts/provision-entra.ps1`](scripts/provision-entra.ps1). It creates the registration,
adds a secret, requests the `email` ID-token claim, and prints a paste-ready PHP config block.

```powershell
# PowerShell 7+. You'll be prompted to sign in (needs Application Developer or higher).
./scripts/provision-entra.ps1 `
    -DisplayName "Acme Intranet - OIDC" `
    -RedirectUri "https://intranet.acme.com/callback.php" `
    -CreateServicePrincipal
```
It installs `Microsoft.Graph.Applications` on first run and connects with the
`Application.ReadWrite.All` scope. Copy the printed **client secret immediately** — Entra shows
it only once.

By default the app is set to **require user assignment** — only users/groups you assign can
sign in, which is the more secure stance. Pass `-NoAssignmentRequired` to leave it open to any
user in the tenant. To grant access to a specific security group, add `-AssignGroup`:

```powershell
./scripts/provision-entra.ps1 `
    -DisplayName "Acme Intranet - OIDC" `
    -RedirectUri "https://intranet.acme.com/callback.php" `
    -AssignGroup "Acme Staff"
```

`-AssignGroup` takes a group display name or object id and is best-effort: **group-based app
assignment requires Entra ID P1 or higher.** On the free tier the script warns and continues —
assign individual users in the portal instead (Enterprise applications → your app → Users and
groups). This is enforced by Entra (unassigned users never get a token) and is independent of
php-oidc's own `authorize` closure, which runs in your app after sign-in; the two complement
each other.

#### Updating an existing app (redirect URIs / secret rotation)

Once the app exists, [`scripts/update-entra.ps1`](scripts/update-entra.ps1) changes its redirect
URIs and rotates the client secret without recreating the registration. Locate the app by
`-ClientId` (preferred) or `-DisplayName`.

```powershell
# Add a redirect URI and rotate the secret, keeping the old one alive (zero-downtime).
./scripts/update-entra.ps1 -DisplayName "Acme Intranet - OIDC" `
    -AddRedirect "https://intranet.acme.com/callback.php" -RenewSecret

# Rotate the secret and remove the previous one.
./scripts/update-entra.ps1 -ClientId <client-id> -RenewSecret -PruneOldSecrets

# Just inspect current redirect URIs and secret expiry.
./scripts/update-entra.ps1 -DisplayName "Acme Intranet - OIDC"
```

By default a renewed secret is added alongside the existing one so nothing breaks mid-deploy;
add `-PruneOldSecrets` to remove the old secret once the new one is live. Use
`-ReplaceRedirects` to swap the whole redirect set, or `-RemoveRedirect` to drop one. When
anything changes it prints an updated paste-ready config block. Supports `-WhatIf` for a dry run.

It can also rename the app (`-RenameDisplayName`, which also renames the enterprise app) and
manage the assignment gate on an existing app with `-AssignGroup` / `-RemoveGroup` /
`-RequireAssignment` / `-NoAssignmentRequired` (creating the enterprise app if needed):

```powershell
# Restrict an existing app to a security group (also requires assignment).
./scripts/update-entra.ps1 -DisplayName "Acme Intranet - OIDC" -AssignGroup "Acme Staff"

# Remove a group's access and rename the app.
./scripts/update-entra.ps1 -DisplayName "Acme Intranet - OIDC" `
    -RemoveGroup "Acme Contractors" -RenameDisplayName "Acme Portal - OIDC"
```

Unlike provisioning, update-entra touches the access posture **only when you pass one of the
assignment options** — a plain secret rotation, rename, or redirect change never alters who can
sign in.

### Option B — Azure CLI

```bash
TENANT=$(az account show --query tenantId -o tsv)

APP_ID=$(az ad app create \
  --display-name "Acme Intranet - OIDC" \
  --sign-in-audience AzureADMyOrg \
  --web-redirect-uris "https://intranet.acme.com/callback.php" \
  --query appId -o tsv)

# Client secret (valid 1 year):
SECRET=$(az ad app credential reset --id "$APP_ID" --years 1 --query password -o tsv)

# Optional: create the enterprise app (service principal)
az ad sp create --id "$APP_ID"

echo "issuer:        https://login.microsoftonline.com/$TENANT/v2.0"
echo "client_id:     $APP_ID"
echo "client_secret: $SECRET"
```

### Option C — Portal (manual), current Entra admin center

1. Sign in to the **[Microsoft Entra admin center](https://entra.microsoft.com)** as at least
   an **Application Developer**.
2. Go to **Entra ID → App registrations → New registration**.
3. **Name** it (e.g. *Acme Intranet - OIDC*).
4. **Supported account types**: choose **Single tenant only – &lt;your tenant&gt;**.
5. **Redirect URI**: select platform **Web**, and enter your callback URL
   (e.g. `https://intranet.acme.com/callback.php`). Then **Register**.
   - To add or change it later: **Manage → Authentication → Add a platform → Web**.
6. On the **Overview** page, copy the **Application (client) ID** and **Directory (tenant) ID**.
   The **Endpoints** button shows the OIDC metadata document URL (your discovery URL).
7. **Manage → Certificates & secrets → Client secrets → New client secret**. Copy the
   **Value** now (shown once).
8. *(Recommended)* **Manage → Token configuration → Add optional claim → ID → `email`** so
   `$user->email()` is populated. `openid`, `profile`, `email` scopes need no admin consent.

Then plug the values in:
```php
$oidc = new Oidc([
    'issuer'        => "https://login.microsoftonline.com/$tenantId/v2.0",
    'client_id'     => '<client-id>',
    'client_secret' => '<client-secret>',
    'redirect_uri'  => 'https://intranet.acme.com/callback.php',
]);
```

> **Multiple apps?** Register one app per web app (each with its own redirect URI + secret).
> The library reads it all from config — nothing app-specific is baked in.

---

## Security notes

- Uses Authorization Code + PKCE; `state` (CSRF) and `nonce` (replay) are enforced.
- The ID-token signature is verified against the provider's JWKS by default; the session id is
  regenerated on login (fixation defense); session cookies are HttpOnly/SameSite=Lax and
  Secure over HTTPS.
- **Always serve over HTTPS** and register HTTPS redirect URIs (localhost excepted for dev).
- Keep secrets out of the web root. Tokens are stored server-side in the session by default.

## How it works

`requireAuth()` → if a session user exists, return it. If the current request is the provider
callback (matching `state` + `code`/`error`), exchange the code at the token endpoint, validate
the ID token (JWKS signature + claims + nonce), run your `authorize` policy, store the session,
and redirect back to the originating URL. Otherwise, redirect to the provider's authorization
endpoint. Discovery and JWKS are fetched once and cached.

## Testing

The crypto and full flow are covered by offline tests that spin up a mock provider and use a
locally-generated RSA key (no network, no real IdP):

```bash
composer test        # or: php tests/run.php
```

## License

MIT © Stan Clemance. See [LICENSE](LICENSE).
