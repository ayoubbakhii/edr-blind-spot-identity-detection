<#
.SYNOPSIS
    Creates a decoy (honeypot) service account with an attractive MSSQL SPN.

.DESCRIPTION
    In real domains, SQL service accounts are prime Kerberoasting targets:
    often privileged, often weakly protected. This decoy looks like one, but
    nothing legitimate ever requests a ticket for it. Any event 4769 for this
    account is therefore malicious (see detection-rules/kibana/honeypot-svc-sqladmin.json).

    Use a long random password: the decoy must be requested, never cracked.

.EXAMPLE
    .\New-HoneypotAccount.ps1 -OU 'OU=Service Accounts,DC=lab,DC=local'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Name = 'svc_sqladmin',
    [string]$OU   = 'OU=LAB,DC=lab,DC=local',
    [string]$Spn  = 'MSSQLSvc/sqlprod.lab.local:1433'
)

Import-Module ActiveDirectory -ErrorAction Stop

$password = Read-Host -AsSecureString "Password for $Name (use 25+ random characters)"

if ($PSCmdlet.ShouldProcess($Name, 'Create honeypot account')) {
    New-ADUser -Name $Name -SamAccountName $Name -Path $OU `
               -Description 'SQL Server service account' `
               -Enabled $true -PasswordNeverExpires $true -AccountPassword $password
    setspn -S $Spn $Name
    Write-Host "Honeypot $Name created with SPN $Spn."
}
