<#
.SYNOPSIS
    Update an existing Microsoft Entra ID app registration: change its redirect URIs and/or
    renew (rotate) the client secret.

.DESCRIPTION
    Companion to provision-entra.ps1 (which creates the app). This script operates on an app
    that already exists. Locate it by -ClientId (the application/client id) or -DisplayName,
    then do any combination of:

      * add / replace / remove redirect URIs (Web.RedirectUris),
      * add a fresh client secret with -RenewSecret (and optionally prune the old ones).

    With no redirect args and no -RenewSecret, it just reports the app's current redirect URIs
    and the expiry of each client secret. When something changes, it prints a ready-to-paste
    php-oidc config block with the current values.

    Uses the Microsoft Graph PowerShell SDK (the current, supported tooling as of 2026 — the
    legacy AzureAD / MSOnline modules are retired). Requires consent to
    Application.ReadWrite.All.

.PARAMETER ClientId
    Application (client) id of the registration to update. Preferred locator.

.PARAMETER DisplayName
    Locate the app by display name instead (must match exactly one registration).

.PARAMETER RenameDisplayName
    New display name for the app registration. The enterprise application (service principal),
    if one exists, is renamed to match.

.PARAMETER AddRedirect
    One or more redirect URIs to add. Merged with the existing set unless -ReplaceRedirects.
    HTTPS required (http://localhost is allowed for local testing).

.PARAMETER RemoveRedirect
    One or more redirect URIs to remove from the existing set.

.PARAMETER ReplaceRedirects
    Replace the whole redirect set with exactly what -AddRedirect specifies.

.PARAMETER RenewSecret
    Add a new client secret and print its value (shown once).

.PARAMETER SecretYears
    Lifetime of the new secret in years (default 1). Entra caps app secrets at 2 years.

.PARAMETER PruneOldSecrets
    After renewing, remove all OTHER secrets on the app (keep only the one just created).
    Without this, the old secret keeps working until it expires — safer for zero-downtime
    rotation, but remember to remove it once the new one is deployed.

.PARAMETER AssignGroup
    Security group (object id or display name) to grant access to the app. Engages assignment
    management: unless -NoAssignmentRequired is given, the app is also set to require assignment.
    Best-effort — if Entra refuses (group-based assignment needs Entra ID P1+), it warns and
    continues.

.PARAMETER RemoveGroup
    Security group (object id or display name) whose access assignment should be removed from
    the app. Also engages assignment management. No-op (with a note) if the group isn't assigned.

.PARAMETER AssignMembersOf
    Security group (object id or display name) whose members are each assigned to the app
    INDIVIDUALLY. This is the free-tier alternative to -AssignGroup (per-user assignment needs no
    Entra ID P1). Includes users in nested groups (transitive). IMPORTANT: it is a point-in-time
    snapshot — later membership changes are not tracked; re-run to reconcile.

.PARAMETER RemoveMembersOf
    Security group (object id or display name) whose members' individual assignments are removed.
    Only affects users currently in the group; someone who already left keeps a stale assignment
    (use -ClearAssignments to fully reset).

.PARAMETER AssignMember
    One or more users (object id or UPN) to assign to the app individually.

.PARAMETER RemoveMember
    One or more users (object id or UPN) whose individual assignment is removed.

.PARAMETER ClearAssignments
    Remove ALL current assignments (users and groups) from the app. Handy before re-flattening a
    group with -AssignMembersOf.

.PARAMETER RequireAssignment
    Set the app to require user assignment (appRoleAssignmentRequired = true) — only assigned
    users/groups can sign in. Implied when -AssignGroup is used.

.PARAMETER NoAssignmentRequired
    Set the app to allow any tenant user (appRoleAssignmentRequired = false). Overrides the
    require-assignment default when engaging assignment management.

.PARAMETER TenantId
    Optional tenant id/domain to sign in to. Defaults to your current Graph context tenant.

.PARAMETER UseDeviceCode
    Sign in with a device code instead of opening a browser (for headless / SSH sessions).

.NOTES
    Assignment is managed only when you ask for it (any of -AssignGroup / -RemoveGroup /
    -AssignMembersOf / -RemoveMembersOf / -AssignMember / -RemoveMember / -ClearAssignments /
    -RequireAssignment / -NoAssignmentRequired). A plain secret rotation, rename, or redirect
    change never alters the app's access posture. When you do engage it, requiring assignment is
    the default (the secure stance); disable with -NoAssignmentRequired. Within a single run the
    order is: clear, then removals, then additions.

.EXAMPLE
    # Add a redirect URI and rotate the secret, keeping the old one alive.
    ./update-entra.ps1 -DisplayName "Acme Intranet - OIDC" `
        -AddRedirect "https://intranet.acme.com/callback.php" -RenewSecret

.EXAMPLE
    # Rotate the secret and remove the previous one.
    ./update-entra.ps1 -ClientId 11111111-1111-1111-1111-111111111111 -RenewSecret -PruneOldSecrets

.EXAMPLE
    # Restrict sign-in to a security group (also requires assignment; needs Entra ID P1+).
    ./update-entra.ps1 -DisplayName "Acme Intranet - OIDC" -AssignGroup "Acme Staff"

.EXAMPLE
    # Remove a group's access and rename the app.
    ./update-entra.ps1 -DisplayName "Acme Intranet - OIDC" `
        -RemoveGroup "Acme Contractors" -RenameDisplayName "Acme Portal - OIDC"

.EXAMPLE
    # Free-tier "group" access: reset assignments, then flatten a group to per-user assignments.
    ./update-entra.ps1 -DisplayName "Acme Intranet - OIDC" `
        -ClearAssignments -AssignMembersOf "Acme Staff"

.EXAMPLE
    # Assign and remove individual users.
    ./update-entra.ps1 -DisplayName "Acme Intranet - OIDC" `
        -AssignMember alice@acme.com,bob@acme.com -RemoveMember carol@acme.com

.EXAMPLE
    # Just inspect current redirect URIs and secret expiry.
    ./update-entra.ps1 -DisplayName "Acme Intranet - OIDC"
#>
#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [string]$ClientId,
    [string]$DisplayName,

    [string]$RenameDisplayName,

    [string[]]$AddRedirect,
    [string[]]$RemoveRedirect,
    [switch]$ReplaceRedirects,

    [switch]$RenewSecret,
    [ValidateRange(1, 2)][int]$SecretYears = 1,
    [switch]$PruneOldSecrets,

    [string]$AssignGroup,
    [string]$RemoveGroup,
    [string]$AssignMembersOf,
    [string]$RemoveMembersOf,
    [string[]]$AssignMember,
    [string[]]$RemoveMember,
    [switch]$ClearAssignments,
    [switch]$RequireAssignment,
    [switch]$NoAssignmentRequired,

    [string]$TenantId,
    # Sign in with a device code (prints a code + URL) instead of opening a browser.
    # Use this on headless/SSH sessions with no local browser.
    [switch]$UseDeviceCode
)

$ErrorActionPreference = 'Stop'

if (-not $ClientId -and -not $DisplayName) {
    throw 'Specify the app to update with -ClientId (preferred) or -DisplayName.'
}
if ($RequireAssignment -and $NoAssignmentRequired) {
    throw 'Pass only one of -RequireAssignment or -NoAssignmentRequired.'
}
$manageAssignment = [bool]$AssignGroup -or [bool]$RemoveGroup -or [bool]$AssignMembersOf -or
    [bool]$RemoveMembersOf -or [bool]$AssignMember -or [bool]$RemoveMember -or $ClearAssignments -or
    $RequireAssignment -or $NoAssignmentRequired

# Resolve a security group by object id or display name to a { id, displayName } object.
function Resolve-EntraGroup([string]$idOrName) {
    if ($idOrName -match '^[0-9a-fA-F-]{36}$') {
        return Invoke-MgGraphRequest -Method GET -OutputType PSObject `
            -Uri "https://graph.microsoft.com/v1.0/groups/$idOrName`?`$select=id,displayName"
    }
    $safe = $idOrName -replace "'", "''"
    $resp = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
        -Uri "https://graph.microsoft.com/v1.0/groups`?`$filter=displayName eq '$safe'&`$select=id,displayName"
    $found = @($resp.value)
    if ($found.Count -eq 0) { throw "No group named '$idOrName' found." }
    if ($found.Count -gt 1) { throw "More than one group named '$idOrName'; pass the object id instead." }
    return $found[0]
}

# Resolve a user by object id or UPN to a { id, userPrincipalName } object.
function Resolve-EntraUser([string]$idOrUpn) {
    $enc = [uri]::EscapeDataString($idOrUpn)
    return Invoke-MgGraphRequest -Method GET -OutputType PSObject `
        -Uri "https://graph.microsoft.com/v1.0/users/$enc`?`$select=id,userPrincipalName"
}

# All transitive USER members of a group (flattens nested groups), with paging.
function Get-EntraGroupUserMembers([string]$groupId) {
    $users = @()
    $uri = "https://graph.microsoft.com/v1.0/groups/$groupId/transitiveMembers/microsoft.graph.user`?`$select=id,userPrincipalName&`$top=999"
    while ($uri) {
        $resp = Invoke-MgGraphRequest -Method GET -OutputType PSObject -Uri $uri
        $users += @($resp.value)
        $uri = $resp.'@odata.nextLink'
    }
    return $users
}

# Assign / unassign a principal (user or group) using a shared principalId -> assignmentId map,
# so a whole batch costs one initial read instead of one read per principal. $map is a hashtable
# (reference type), so these mutate it in place for the caller.
function Add-EntraAssignment($sp, $map, [string]$principalId, [string]$label) {
    if ($map.ContainsKey($principalId)) { Write-Host "  $label already assigned." -ForegroundColor DarkGray; return }
    $res = New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -BodyParameter @{
        PrincipalId = $principalId; ResourceId = $sp.Id
        AppRoleId   = '00000000-0000-0000-0000-000000000000'   # default access (no app roles defined)
    }
    $map[$principalId] = $res.Id
    Write-Host "  assigned $label." -ForegroundColor Green
}
function Remove-EntraAssignment($sp, $map, [string]$principalId, [string]$label) {
    if (-not $map.ContainsKey($principalId)) { Write-Host "  $label not assigned; nothing to remove." -ForegroundColor DarkGray; return }
    Remove-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -AppRoleAssignmentId $map[$principalId]
    $map.Remove($principalId)
    Write-Host "  removed $label." -ForegroundColor Green
}

# --- 1. Ensure the Graph Applications module is available -------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
    Write-Host "Installing Microsoft.Graph.Applications module (current user scope)..." -ForegroundColor Cyan
    Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Applications

# --- 2. Connect (needs permission to modify app registrations) -------------------------
$scopes = @('Application.ReadWrite.All')
if ($AssignGroup -or $RemoveGroup -or $AssignMembersOf -or $RemoveMembersOf) { $scopes += 'Group.Read.All' }
if ($AssignMembersOf -or $RemoveMembersOf) { $scopes += 'GroupMember.Read.All' }
if ($AssignMember -or $RemoveMember)       { $scopes += 'User.ReadBasic.All' }
if ($AssignGroup -or $RemoveGroup -or $AssignMembersOf -or $RemoveMembersOf -or
    $AssignMember -or $RemoveMember -or $ClearAssignments) { $scopes += 'AppRoleAssignment.ReadWrite.All' }
$connectArgs = @{ Scopes = ($scopes | Select-Object -Unique) }
if ($TenantId)      { $connectArgs.TenantId = $TenantId }
if ($UseDeviceCode) { $connectArgs.UseDeviceCode = $true }
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph @connectArgs | Out-Null

try {
    $tenant = (Get-MgContext).TenantId
    $issuer = "https://login.microsoftonline.com/$tenant/v2.0"

    # --- 3. Locate the app -------------------------------------------------------------
    if ($ClientId) {
        $app = Get-MgApplication -Filter "appId eq '$ClientId'" -ErrorAction Stop
    } else {
        $safeName = $DisplayName -replace "'", "''"
        $app = @(Get-MgApplication -Filter "displayName eq '$safeName'" -ErrorAction Stop)
        if ($app.Count -gt 1) { throw "More than one app is named '$DisplayName'; use -ClientId to disambiguate." }
        $app = $app | Select-Object -First 1
    }
    if (-not $app) { throw 'App registration not found.' }
    Write-Host "Found '$($app.DisplayName)' (client id $($app.AppId))." -ForegroundColor Green

    # --- 3b. Rename ---------------------------------------------------------------------
    if ($RenameDisplayName -and $RenameDisplayName -ne $app.DisplayName -and
        $PSCmdlet.ShouldProcess($app.DisplayName, "Rename to '$RenameDisplayName'")) {
        Update-MgApplication -ApplicationId $app.Id -DisplayName $RenameDisplayName
        # Keep the enterprise app (service principal) name in sync if one exists.
        $spRename = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
        if ($spRename) { Update-MgServicePrincipal -ServicePrincipalId $spRename.Id -DisplayName $RenameDisplayName }
        Write-Host "Renamed to '$RenameDisplayName'." -ForegroundColor Green
        $app.DisplayName = $RenameDisplayName   # so later messages use the new name
    }

    $current = @($app.Web.RedirectUris)
    Write-Host ("Current redirect URIs: " + $(if ($current) { $current -join ', ' } else { '(none)' }))

    # --- 4. Redirect URIs --------------------------------------------------------------
    $wanted = [System.Collections.Generic.List[string]]::new()
    if (-not $ReplaceRedirects) { $current | ForEach-Object { $wanted.Add($_) } }
    if ($AddRedirect) {
        foreach ($u in $AddRedirect) { if ($wanted -notcontains $u) { $wanted.Add($u) } }
    }
    if ($RemoveRedirect) {
        foreach ($u in $RemoveRedirect) { [void]$wanted.Remove($u) }
    }

    $redirectChanged = $ReplaceRedirects -or $AddRedirect -or $RemoveRedirect
    if ($redirectChanged) {
        $finalSet = @($wanted)
        if (($finalSet -join '|') -eq ($current -join '|')) {
            Write-Host 'Redirect URIs already match; nothing to change.' -ForegroundColor DarkGray
            $redirectChanged = $false
        } elseif ($PSCmdlet.ShouldProcess($app.DisplayName, "Set redirect URIs to: $($finalSet -join ', ')")) {
            Update-MgApplication -ApplicationId $app.Id -Web @{ RedirectUris = $finalSet }
            Write-Host "Redirect URIs now: $($finalSet -join ', ')" -ForegroundColor Green
        }
    }
    $primaryRedirect = @($wanted) | Select-Object -First 1

    # --- 5. Renew secret ---------------------------------------------------------------
    $newSecret = ''
    if ($RenewSecret) {
        if ($PSCmdlet.ShouldProcess($app.DisplayName, "Add a new client secret valid $SecretYears year(s)")) {
            $cred = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
                DisplayName = 'php-oidc'; EndDateTime = (Get-Date).AddYears($SecretYears) }
            $newSecret = $cred.SecretText
            Write-Host "New client secret (shown once): $newSecret" -ForegroundColor Yellow
            Write-Host "  key id $($cred.KeyId), expires $($cred.EndDateTime.ToString('yyyy-MM-dd'))." -ForegroundColor DarkGray

            if ($PruneOldSecrets) {
                $refreshed = Get-MgApplication -ApplicationId $app.Id
                foreach ($pw in $refreshed.PasswordCredentials) {
                    if ($pw.KeyId -ne $cred.KeyId -and
                        $PSCmdlet.ShouldProcess($app.DisplayName, "Remove old secret $($pw.KeyId)")) {
                        Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId $pw.KeyId
                        Write-Host "  removed old secret $($pw.KeyId)." -ForegroundColor DarkGray
                    }
                }
            }
        }
    }

    # --- 5b. Assignment gate + group/user assignment (only when asked) -----------------
    # These live on the service principal (enterprise app), so ensure one exists first.
    if ($manageAssignment) {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
        if (-not $sp) {
            if ($PSCmdlet.ShouldProcess($app.DisplayName, 'Create service principal (enterprise application)')) {
                Write-Host "No enterprise application found; creating the service principal..." -ForegroundColor Cyan
                $sp = New-MgServicePrincipal -AppId $app.AppId
            }
        }

        if ($sp) {
            $assignmentRequired = -not $NoAssignmentRequired
            if ($PSCmdlet.ShouldProcess($app.DisplayName, "Set user assignment required = $assignmentRequired")) {
                Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AppRoleAssignmentRequired:$assignmentRequired
                Write-Host "User assignment required = $assignmentRequired." -ForegroundColor Green
            }

            # Read the current assignments once; the helpers keep this map in sync as we go.
            $assignMap = @{}
            foreach ($a in (Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -All)) {
                $assignMap[$a.PrincipalId] = $a.Id
            }

            # 1) Clear, then removals, then additions — so a "reset and re-flatten" run is coherent.
            if ($ClearAssignments -and $PSCmdlet.ShouldProcess($app.DisplayName, "Remove ALL $($assignMap.Count) assignment(s)")) {
                $n = $assignMap.Count
                foreach ($key in @($assignMap.Keys)) {
                    Remove-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -AppRoleAssignmentId $assignMap[$key]
                }
                $assignMap.Clear()
                Write-Host "Cleared $n assignment(s)." -ForegroundColor Green
            }

            if ($RemoveGroup -and $PSCmdlet.ShouldProcess($app.DisplayName, "Remove group '$RemoveGroup'")) {
                try {
                    $group = Resolve-EntraGroup $RemoveGroup
                    Remove-EntraAssignment $sp $assignMap $group.id "group '$($group.displayName)'"
                } catch { Write-Warning "Could not remove group '$RemoveGroup': $($_.Exception.Message)" }
            }

            if ($RemoveMembersOf -and $PSCmdlet.ShouldProcess($app.DisplayName, "Remove all members of group '$RemoveMembersOf'")) {
                try {
                    $group = Resolve-EntraGroup $RemoveMembersOf
                    $members = Get-EntraGroupUserMembers $group.id
                    Write-Host "Unassigning $($members.Count) user member(s) of '$($group.displayName)'..." -ForegroundColor Cyan
                    foreach ($u in $members) { Remove-EntraAssignment $sp $assignMap $u.id "user '$($u.userPrincipalName)'" }
                } catch { Write-Warning "Could not remove members of '$RemoveMembersOf': $($_.Exception.Message)" }
            }

            foreach ($m in @($RemoveMember)) {
                if ($PSCmdlet.ShouldProcess($app.DisplayName, "Remove user '$m'")) {
                    try {
                        $u = Resolve-EntraUser $m
                        Remove-EntraAssignment $sp $assignMap $u.id "user '$($u.userPrincipalName)'"
                    } catch { Write-Warning "Could not remove user '$m': $($_.Exception.Message)" }
                }
            }

            if ($AssignGroup -and $PSCmdlet.ShouldProcess($app.DisplayName, "Assign group '$AssignGroup'")) {
                try {
                    $group = Resolve-EntraGroup $AssignGroup
                    Add-EntraAssignment $sp $assignMap $group.id "group '$($group.displayName)'"
                } catch {
                    Write-Warning "Could not assign group '$AssignGroup': $($_.Exception.Message)"
                    Write-Warning "Group-based app assignment requires Entra ID P1 or higher. On the free tier, assign individual users with -AssignMember / -AssignMembersOf instead."
                }
            }

            if ($AssignMembersOf -and $PSCmdlet.ShouldProcess($app.DisplayName, "Assign all members of group '$AssignMembersOf'")) {
                try {
                    $group = Resolve-EntraGroup $AssignMembersOf
                    $members = Get-EntraGroupUserMembers $group.id
                    Write-Host "Assigning $($members.Count) user member(s) of '$($group.displayName)' (transitive)..." -ForegroundColor Cyan
                    foreach ($u in $members) { Add-EntraAssignment $sp $assignMap $u.id "user '$($u.userPrincipalName)'" }
                    Write-Warning "This is a point-in-time snapshot of the group; membership changes are NOT tracked. Re-run to reconcile."
                } catch { Write-Warning "Could not assign members of '$AssignMembersOf': $($_.Exception.Message)" }
            }

            foreach ($m in @($AssignMember)) {
                if ($PSCmdlet.ShouldProcess($app.DisplayName, "Assign user '$m'")) {
                    try {
                        $u = Resolve-EntraUser $m
                        Add-EntraAssignment $sp $assignMap $u.id "user '$($u.userPrincipalName)'"
                    } catch { Write-Warning "Could not assign user '$m': $($_.Exception.Message)" }
                }
            }
        }
    }

    # --- 6. Secret inventory -----------------------------------------------------------
    $inv = (Get-MgApplication -ApplicationId $app.Id).PasswordCredentials
    if ($inv) {
        Write-Host "`nClient secrets on this app:"
        $inv | Sort-Object EndDateTime | ForEach-Object {
            $days = [int]([datetime]$_.EndDateTime - (Get-Date)).TotalDays
            $state = if ($days -lt 0) { 'EXPIRED' } elseif ($days -lt 30) { "expires in $days d" } else { "expires $($_.EndDateTime.ToString('yyyy-MM-dd'))" }
            Write-Host ("  - {0}  {1}  {2}" -f $_.KeyId, $_.DisplayName, $state)
        }
    }

    # --- 7. Output a paste-ready config block when something changed --------------------
    if ($redirectChanged -or $newSecret) {
        $secretLine = if ($newSecret) { "'$newSecret'" } else { "'...',  // unchanged; keep your existing secret" }
        Write-Host ""
        Write-Host "-------- Paste into your php-oidc config --------" -ForegroundColor Yellow
        @"
`$oidc = new Sclemance\Oidc\Oidc([
    'issuer'        => '$issuer',
    'client_id'     => '$($app.AppId)',
    'client_secret' => $secretLine,
    'redirect_uri'  => '$primaryRedirect',
]);
"@ | Write-Host
        Write-Host "-------------------------------------------------" -ForegroundColor Yellow
        if ($newSecret) {
            Write-Warning "The client secret is shown ONCE. Store it now (e.g. in your app's off-web-root config or a secret manager)."
        }
    }
}
finally {
    Disconnect-MgGraph | Out-Null
}
