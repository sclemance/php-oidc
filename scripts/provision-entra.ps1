<#
.SYNOPSIS
    Provision a Microsoft Entra ID app registration.

.DESCRIPTION
    Creates a single-tenant web app registration with the given redirect URI(s), adds a
    client secret, requests the `email` optional claim in the ID token, and prints a
    ready-to-paste PHP config block (issuer, client_id, client_secret, redirect_uri).

    Uses the Microsoft Graph PowerShell SDK (the current, supported tooling as of 2026 — the
    legacy AzureAD / MSOnline modules are retired). Verified against the Entra admin center
    and Microsoft.Graph.Applications cmdlets, July 2026.

    Before creating anything, it verifies the signed-in user holds a directory role that can
    register applications (Application Developer, Application Administrator, Cloud Application
    Administrator, or Global Administrator) and stops early with guidance otherwise. Requires
    consent to Application.ReadWrite.All, RoleManagement.Read.Directory, and User.Read.

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
    up under Enterprise applications and can be assigned/conditional-access-scoped. Implied
    whenever assignment is managed (the default) or -AssignGroup is used.

.PARAMETER NoAssignmentRequired
    By default the app is set to require user assignment (appRoleAssignmentRequired = true), so
    only assigned users/groups can sign in — the more secure stance. Pass this switch to leave
    the app open to any user in the tenant instead.

.PARAMETER AssignGroup
    Security group (object id or display name) to grant access to the app. Attempted only if
    given; if Entra refuses (group-based assignment needs Entra ID P1+), it warns and continues.

.PARAMETER UseDeviceCode
    Sign in with a device code instead of opening a browser (for headless / SSH sessions).

.PARAMETER Force
    Skip the preflight directory-role check (e.g. tenant self-service registration is allowed,
    or a qualifying role is PIM-eligible but not currently activated).

.EXAMPLE
    ./provision-entra.ps1 -DisplayName "Acme Intranet - OIDC" `
        -RedirectUri "https://intranet.acme.com/callback.php" -CreateServicePrincipal

.EXAMPLE
    # Restrict sign-in to a security group (requires Entra ID P1+ for group assignment).
    ./provision-entra.ps1 -DisplayName "Acme Intranet - OIDC" `
        -RedirectUri "https://intranet.acme.com/callback.php" -AssignGroup "Acme Staff"
#>
#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,

    [Parameter(Mandatory = $true)]
    [string[]]$RedirectUri,

    [string]$TenantId,

    [ValidateRange(1, 2)]
    [int]$SecretYears = 1,

    [switch]$CreateServicePrincipal,

    # Leave the app open to any tenant user. By default the app requires user assignment.
    [switch]$NoAssignmentRequired,

    # Security group (object id or display name) to grant access to. Best-effort: needs P1+.
    [string]$AssignGroup,

    # Sign in with a device code (prints a code + URL) instead of opening a browser.
    # Use this on headless/SSH sessions with no local browser.
    [switch]$UseDeviceCode,

    # Skip the preflight directory-role check (e.g. when your tenant allows self-service app
    # registration, or your qualifying role is PIM-eligible but not currently activated).
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# --- 1. Ensure the Graph Applications module is available -------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
    Write-Host "Installing Microsoft.Graph.Applications module (current user scope)..." -ForegroundColor Cyan
    Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Applications

# --- 2. Connect (needs permission to create app registrations) -------------------------
# RoleManagement.Read.Directory + User.Read let us verify the signed-in user's role before
# attempting to create anything. Application.ReadWrite.All is needed to create the app.
$scopes = @('Application.ReadWrite.All', 'RoleManagement.Read.Directory', 'User.Read')
if ($AssignGroup) { $scopes += @('Group.Read.All', 'AppRoleAssignment.ReadWrite.All') }
$connectArgs = @{ Scopes = $scopes }
if ($TenantId)      { $connectArgs.TenantId = $TenantId }
if ($UseDeviceCode) { $connectArgs.UseDeviceCode = $true }
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph @connectArgs | Out-Null

$context  = Get-MgContext
$tenant   = $context.TenantId
$issuer   = "https://login.microsoftonline.com/$tenant/v2.0"

# --- 2b. Preflight: does the signed-in user hold a role that can register apps? ---------
# Built-in directory roles (by well-known template ID) that can create app registrations.
$rolesThatCanRegister = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    'cf1c38e5-3621-4004-a7cb-879624dced7c' = 'Application Developer'
}

Write-Host "Checking your directory role..." -ForegroundColor Cyan
$held = @()
try {
    $me = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
        -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'
    $signedInAs = $me.userPrincipalName
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($me.id)'&`$expand=roleDefinition"
    $assignments = Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri $uri
    foreach ($a in $assignments.value) {
        $tid = $a.roleDefinition.templateId
        $rid = $a.roleDefinition.id
        foreach ($k in @($tid, $rid)) {
            if ($k -and $rolesThatCanRegister.ContainsKey($k)) { $held += $rolesThatCanRegister[$k] }
        }
    }
    $held = $held | Select-Object -Unique
} catch {
    Write-Warning "Could not verify your directory role ($($_.Exception.Message))."
    if (-not $Force) {
        Write-Warning "Re-run with -Force to proceed anyway."
        Disconnect-MgGraph | Out-Null
        exit 1
    }
}

if ($held.Count -gt 0) {
    Write-Host "Role OK: $signedInAs holds '$($held -join "', '")'." -ForegroundColor Green
} elseif ($Force) {
    Write-Warning "No app-registration role detected for $signedInAs; continuing because -Force was set."
} else {
    Write-Host ""
    Write-Warning "$signedInAs does not hold a role that can register applications."
    Write-Host "  Required (any one): Application Developer, Application Administrator," -ForegroundColor Yellow
    Write-Host "  Cloud Application Administrator, or Global Administrator." -ForegroundColor Yellow
    Write-Host "  Note: if the role is PIM-eligible, activate it first; or your tenant may allow" -ForegroundColor Yellow
    Write-Host "  self-service app registration - in that case re-run with -Force." -ForegroundColor Yellow
    Disconnect-MgGraph | Out-Null
    exit 1
}

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

# --- 5. Service principal (enterprise app), assignment gate, group assignment -----------
# Requiring assignment and assigning a group both live on the service principal, so create it
# whenever we manage assignment (the default) or a group was requested.
$assignmentRequired = -not $NoAssignmentRequired
$sp = $null
if ($CreateServicePrincipal -or $assignmentRequired -or $AssignGroup) {
    Write-Host "Creating service principal (enterprise application)..." -ForegroundColor Cyan
    $sp = New-MgServicePrincipal -AppId $clientId

    Write-Host "Setting user assignment required = $assignmentRequired..." -ForegroundColor Cyan
    Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AppRoleAssignmentRequired:$assignmentRequired

    if ($AssignGroup) {
        try {
            if ($AssignGroup -match '^[0-9a-fA-F-]{36}$') {
                $group = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
                    -Uri "https://graph.microsoft.com/v1.0/groups/$AssignGroup`?`$select=id,displayName"
            } else {
                $safeGroup = $AssignGroup -replace "'", "''"
                $resp = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
                    -Uri "https://graph.microsoft.com/v1.0/groups`?`$filter=displayName eq '$safeGroup'&`$select=id,displayName"
                $found = @($resp.value)
                if ($found.Count -eq 0) { throw "No group named '$AssignGroup' found." }
                if ($found.Count -gt 1) { throw "More than one group named '$AssignGroup'; pass the object id instead." }
                $group = $found[0]
            }
            New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -BodyParameter @{
                PrincipalId = $group.id; ResourceId = $sp.Id
                AppRoleId   = '00000000-0000-0000-0000-000000000000'   # default access (no app roles defined)
            } | Out-Null
            Write-Host "Assigned group '$($group.displayName)' to the app." -ForegroundColor Green
        } catch {
            Write-Warning "Could not assign group '$AssignGroup': $($_.Exception.Message)"
            Write-Warning "Group-based app assignment requires Entra ID P1 or higher. On the free tier, assign individual users in the portal (Enterprise applications > your app > Users and groups)."
        }
    }
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
if ($sp) { Write-Host "Assignment required  : $assignmentRequired$(if ($AssignGroup) { " (group: $AssignGroup)" })" }
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
