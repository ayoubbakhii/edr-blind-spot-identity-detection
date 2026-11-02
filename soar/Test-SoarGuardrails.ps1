<#
.SYNOPSIS
    Replays the four guardrail tests against the SOAR listener.

.DESCRIPTION
    Sends, in order:
      1. an unauthenticated request             -> expected REJECTED (401)
      2. a signed request for a protected admin -> expected BLOCKED  (403)
      3. a signed request for the test account  -> expected ACTION   (200)
      4. the same request again                 -> expected IGNORED  (200)

    Prerequisites: the listener is running with $env:SOAR_HMAC_KEY set, and
    the test account exists and is enabled. Re-enable it after the test:
      Enable-ADAccount -Identity test.soar

.EXAMPLE
    $env:SOAR_HMAC_KEY = '<same key as the listener>'
    .\Test-SoarGuardrails.ps1 -Uri 'http://192.168.56.20:8888/'
#>
[CmdletBinding()]
param(
    [string]$Uri              = 'http://192.168.56.20:8888/',
    [string]$TestAccount      = 'test.soar',
    [string]$ProtectedAccount = 'adm.protected'
)

$key = $env:SOAR_HMAC_KEY
if (-not $key) { throw 'Set $env:SOAR_HMAC_KEY (same value as on the listener).' }

function Get-Signature([string]$Body) {
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($key))
    try { -join ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Body)) | ForEach-Object { $_.ToString('x2') }) }
    finally { $hmac.Dispose() }
}

function Send-Test([string]$Name, [string]$Body, [hashtable]$Headers) {
    try {
        $r = Invoke-RestMethod -Uri $Uri -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($Body)) `
                               -ContentType 'application/json' -Headers $Headers
        '{0,-28} -> 200 {1}' -f $Name, $r.status
    } catch {
        '{0,-28} -> {1}' -f $Name, $_.Exception.Message
    }
}

$protectedBody = '{"user":"' + $ProtectedAccount + '"}'
$testBody      = '{"user":"' + $TestAccount + '@LAB.LOCAL"}'   # suffix on purpose: tests normalisation

Send-Test '1. No authentication'      $testBody      @{}
Send-Test '2. Protected account'      $protectedBody @{ 'X-Signature' = (Get-Signature $protectedBody) }
Send-Test '3. Legitimate action'      $testBody      @{ 'X-Signature' = (Get-Signature $testBody) }
Send-Test '4. Replay (idempotency)'   $testBody      @{ 'X-Signature' = (Get-Signature $testBody) }

Write-Host "`nCheck the listener log (C:\soar-actions.log): REJECTED, BLOCKED, ACTION, IGNORED."
