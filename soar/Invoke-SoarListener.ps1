<#
.SYNOPSIS
    Minimal SOAR listener: disables an Active Directory account when a
    high-fidelity Kibana alert calls this webhook.

.DESCRIPTION
    Runs on the domain controller (lab: VM2, 192.168.56.20) and listens on
    HTTP port 8888. Each request goes through four guardrails:

      1. Authentication  - valid HMAC-SHA256 signature of the body (X-Signature)
                           OR valid shared token (X-Auth-Token). Otherwise REJECTED.
      2. Protect-list    - critical accounts are never disabled. BLOCKED.
      3. Idempotency     - an already-disabled account is left alone. IGNORED.
      4. Audit log       - every decision is timestamped (UTC) in the log file.

    Expected JSON body:  { "user": "jdoe" }  or  { "user": "jdoe@LAB.LOCAL" }
    The domain suffix is stripped: event 4769 returns user@DOMAIN, while
    event 4768 returns the bare name, and Disable-ADAccount needs the bare name.

.NOTES
    Secrets come from environment variables, never from this file:
      $env:SOAR_TOKEN     shared token sent by the Kibana webhook connector
      $env:SOAR_HMAC_KEY  key for HMAC-SHA256 signed requests (optional)

    Lab use only. In production: run behind TLS, start in alert-only mode
    (-WhatIfMode), and restrict the port to the SIEM's IP in the firewall.

.EXAMPLE
    $env:SOAR_TOKEN = '<long random token>'
    .\Invoke-SoarListener.ps1 -Port 8888 -ProtectedAccounts 'Administrator','krbtgt','adm.protected'
#>
[CmdletBinding()]
param(
    [int]      $Port              = 8888,
    [string]   $LogPath           = 'C:\soar-actions.log',
    [string[]] $ProtectedAccounts = @('Administrator', 'krbtgt', 'adm.protected'),
    [switch]   $WhatIfMode        # log the decision but do not disable anything
)

Set-StrictMode -Version Latest
Import-Module ActiveDirectory -ErrorAction Stop

$Token   = $env:SOAR_TOKEN
$HmacKey = $env:SOAR_HMAC_KEY
if (-not $Token -and -not $HmacKey) {
    throw 'Set $env:SOAR_TOKEN and/or $env:SOAR_HMAC_KEY before starting the listener.'
}

function Write-SoarLog {
    param([string]$Decision, [string]$Account, [string]$Detail)
    $line = '{0} | {1,-8} | {2} | {3}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'),
                                          $Decision, $Account, $Detail
    Add-Content -Path $LogPath -Value $line
    Write-Host $line
}

# Constant-time comparison, so response timing does not leak the secret
function Test-SecretEquals {
    param([string]$A, [string]$B)
    if ([string]::IsNullOrEmpty($A) -or [string]::IsNullOrEmpty($B) -or $A.Length -ne $B.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) { $diff = $diff -bor ([int][char]$A[$i] -bxor [int][char]$B[$i]) }
    return ($diff -eq 0)
}

function Get-HmacSha256Hex {
    param([string]$Key, [string]$Message)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($Key))
    try {
        $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Message))
        return -join ($hash | ForEach-Object { $_.ToString('x2') })
    } finally { $hmac.Dispose() }
}

function Test-Authenticated {
    param($Request, [string]$Body)
    $signature = $Request.Headers['X-Signature']
    if ($script:HmacKey -and $signature) {
        $expected = Get-HmacSha256Hex -Key $script:HmacKey -Message $Body
        $received = ($signature -replace '^sha256=', '').ToLowerInvariant()
        if (Test-SecretEquals $expected $received) { return $true }
    }
    # Note: PowerShell variable names are case-insensitive, so never reuse $Token here
    $headerToken = $Request.Headers['X-Auth-Token']
    if ($script:Token -and $headerToken -and (Test-SecretEquals $script:Token $headerToken)) { return $true }
    return $false
}

function Send-Response {
    param($Context, [int]$Status, [string]$Message)
    $bytes = [Text.Encoding]::UTF8.GetBytes((@{ status = $Message } | ConvertTo-Json -Compress))
    $Context.Response.StatusCode  = $Status
    $Context.Response.ContentType = 'application/json'
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.Close()
}

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://+:$Port/")
$listener.Start()
Write-Host "SOAR listener running on port $Port (log: $LogPath). Ctrl+C to stop."

try {
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $req = $ctx.Request
        $src = $req.RemoteEndPoint.Address.ToString()

        if ($req.HttpMethod -ne 'POST') { Send-Response $ctx 405 'method not allowed'; continue }

        $reader = [System.IO.StreamReader]::new($req.InputStream, [Text.Encoding]::UTF8)
        $body = $reader.ReadToEnd()
        $reader.Dispose()

        # Guardrail 1: authentication
        if (-not (Test-Authenticated -Request $req -Body $body)) {
            Write-SoarLog 'REJECTED' '-' "invalid authentication from $src"
            Send-Response $ctx 401 'rejected: invalid authentication'
            continue
        }

        try { $json = $body | ConvertFrom-Json -ErrorAction Stop }
        catch { Write-SoarLog 'ERROR' '-' "invalid JSON from $src"; Send-Response $ctx 400 'invalid json'; continue }

        # Normalise: user@LAB.LOCAL -> user ; allow only safe sAMAccountName characters
        $userProp = $json.PSObject.Properties['user']
        $account  = if ($userProp) { ([string]$userProp.Value -split '@')[0].Trim() } else { '' }
        if ($account -notmatch '^[A-Za-z0-9._-]{1,64}$') {
            Write-SoarLog 'ERROR' '-' "invalid or missing account name from $src"
            Send-Response $ctx 400 'invalid account name'
            continue
        }

        # Guardrail 2: protect-list (case-insensitive)
        if ($ProtectedAccounts -contains $account) {
            Write-SoarLog 'BLOCKED' $account "protected account, request from $src"
            Send-Response $ctx 403 'blocked: protected account'
            continue
        }

        try { $adUser = Get-ADUser -Identity $account -Properties Enabled -ErrorAction Stop }
        catch { Write-SoarLog 'ERROR' $account 'account not found'; Send-Response $ctx 404 'account not found'; continue }

        # Guardrail 3: idempotency
        if (-not $adUser.Enabled) {
            Write-SoarLog 'IGNORED' $account 'already disabled'
            Send-Response $ctx 200 'ignored: already disabled'
            continue
        }

        if ($WhatIfMode) {
            Write-SoarLog 'WHATIF' $account 'would disable (alert-only mode)'
            Send-Response $ctx 200 'whatif: would disable'
            continue
        }

        Disable-ADAccount -Identity $adUser
        Write-SoarLog 'ACTION' $account "account disabled, request from $src"
        Send-Response $ctx 200 'action: account disabled'
    }
}
finally {
    $listener.Stop()
    $listener.Close()
}
