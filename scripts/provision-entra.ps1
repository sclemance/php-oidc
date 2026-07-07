#Requires -Version 7.0
<#
.SYNOPSIS
    Provision a Microsoft Entra ID app registration for use with sclemance/php-oidc.

.DESCRIPTION
    Creates a single-tenant web app registration with the given redirect URI(s), adds a
    client secret, requests the `email` optional claim in the ID token, and prints a
    ready-to-paste PHP config block (issuer, client_id, client_secret, redirect_uri).

    Uses the Microsoft Graph PowerShell SDK (the current, supported tooling as of 2026 — the
    legacy AzureAD / MSOnline modules are retired). Verified against the Entra admin center
    and Microsoft.Graph.Applications cmdlets, July 2026.

.PARAMETER DisplayName
    The app registration display name (e.g. "Acme Intranet - OIDC").

.PARAMETER RedirectUri
    One or more redirect URIs. This is the URL php-oidc handles the callback on — either the
    page you protect (single-file pattern) or your dedicated callback.php. HTTPS required
    (http://localhost is allowed for local testing).

.PARAMETER TenantId
    Optional tenant id/domain to sign in to. Defaults to your current Graph context tenant.

.PARAMETER SecretYears
    Client secret lifetime in years (default 1). Entra caps app secrets at 2 years.

.PARAMETER CreateServicePrincipal
    Also create the enterprise application (service principal). Recommended so the app shows
    up under Enterprise applications and can be assigned/conditional-access-scoped.

.EXAMPLE
    ./provision-entra.ps1 -DisplayName "Acme Intranet - OIDC" `
        -RedirectUri "https://intranet.acme.com/callback.php" -CreateServicePrincipal
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,

    [Parameter(Mandatory = $true)]
    [string[]]$RedirectUri,

    [string]$TenantId,

    [ValidateRange(1, 2)]
    [int]$SecretYears = 1,

    [switch]$CreateServicePrincipal
)

$ErrorActionPreference = 'Stop'

# --- 1. Ensure the Graph Applications module is available -------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
    Write-Host "Installing Microsoft.Graph.Applications module (current user scope)..." -ForegroundColor Cyan
    Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Applications

# --- 2. Connect (needs permission to create app registrations) -------------------------
$connectArgs = @{ Scopes = 'Application.ReadWrite.All' }
if ($TenantId) { $connectArgs.TenantId = $TenantId }
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph @connectArgs | Out-Null

$context  = Get-MgContext
$tenant   = $context.TenantId
$issuer   = "https://login.microsoftonline.com/$tenant/v2.0"

# --- 3. Create the app registration ----------------------------------------------------
Write-Host "Creating app registration '$DisplayName'..." -ForegroundColor Cyan

# Request the email claim in the ID token so php-oidc's $user->email() is populated.
$optionalClaims = @{
    IdToken = @(
        @{ Name = 'email';              Essential = $false }
        @{ Name = 'preferred_username'; Essential = $false }
    )
}

$app = New-MgApplication `
    -DisplayName    $DisplayName `
    -SignInAudience 'AzureADMyOrg' `
    -Web            @{ RedirectUris = $RedirectUri } `
    -OptionalClaims $optionalClaims

$appObjectId = $app.Id       # object id (used to manage the app)
$clientId    = $app.AppId    # application (client) id (used in config)

# --- 4. Add a client secret ------------------------------------------------------------
Write-Host "Adding a client secret (valid $SecretYears year(s))..." -ForegroundColor Cyan
$secret = Add-MgApplicationPassword -ApplicationId $appObjectId -PasswordCredential @{
    DisplayName = 'php-oidc'
    EndDateTime = (Get-Date).AddYears($SecretYears)
}
$clientSecret = $secret.SecretText

# --- 5. Optionally create the service principal (enterprise app) ------------------------
if ($CreateServicePrincipal) {
    Write-Host "Creating service principal (enterprise application)..." -ForegroundColor Cyan
    New-MgServicePrincipal -AppId $clientId | Out-Null
}

# --- 6. Output -------------------------------------------------------------------------
$primaryRedirect = $RedirectUri[0]

Write-Host ""
Write-Host "==================== Entra app provisioned ====================" -ForegroundColor Green
Write-Host "Tenant ID           : $tenant"
Write-Host "Application (client) : $clientId"
Write-Host "Client secret        : $clientSecret"
Write-Host "Secret expires       : $((Get-Date).AddYears($SecretYears).ToString('yyyy-MM-dd'))"
Write-Host "Issuer               : $issuer"
Write-Host "Discovery URL        : $issuer/.well-known/openid-configuration"
Write-Host "Redirect URI(s)      : $($RedirectUri -join ', ')"
Write-Host ""
Write-Host "-------- Paste into your php-oidc config --------" -ForegroundColor Yellow
@"
`$oidc = new Sclemance\Oidc\Oidc([
    'issuer'        => '$issuer',
    'client_id'     => '$clientId',
    'client_secret' => '$clientSecret',
    'redirect_uri'  => '$primaryRedirect',
]);
"@ | Write-Host
Write-Host "-------------------------------------------------" -ForegroundColor Yellow
Write-Host ""
Write-Warning "The client secret is shown ONCE. Store it now (e.g. in your app's off-web-root config or a secret manager)."

Disconnect-MgGraph | Out-Null
