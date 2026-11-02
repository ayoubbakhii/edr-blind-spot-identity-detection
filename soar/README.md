# SOAR: automated account disabling

```
Kibana alert (high-fidelity rule)
   └─► Webhook connector  (POST, X-Auth-Token header)
          └─► Invoke-SoarListener.ps1 on the DC (port 8888)
                 ├─ 1. authentication   → REJECTED if invalid
                 ├─ 2. protect-list     → BLOCKED for critical accounts
                 ├─ 3. idempotency      → IGNORED if already disabled
                 ├─ Disable-ADAccount   → ACTION
                 └─ 4. audit log        → C:\soar-actions.log
```

## Files

| File | Purpose |
|---|---|
| [`Invoke-SoarListener.ps1`](Invoke-SoarListener.ps1) | The listener, with the 4 guardrails and an alert-only mode (`-WhatIfMode`) |
| [`Test-SoarGuardrails.ps1`](Test-SoarGuardrails.ps1) | Replays the 4 guardrail tests |
| [`kibana-webhook-connector.md`](kibana-webhook-connector.md) | How to wire Kibana to the listener |

> **About this code:** the lab listener's logic (guardrails, suffix normalisation, log format) is documented in the project report. This script is a clean rewrite of that design for publication, with secrets moved to environment variables. Its guardrail flow was verified end to end with `Test-SoarGuardrails.ps1` (with the AD cmdlets simulated); test it against a real lab domain before relying on it.

## Run it (on the domain controller)

```powershell
# 1. Open the port to the SIEM only
New-NetFirewallRule -DisplayName 'SOAR listener 8888' -Direction Inbound -Protocol TCP `
    -LocalPort 8888 -RemoteAddress 192.168.56.40 -Action Allow

# 2. Set secrets (never hard-code them)
$env:SOAR_TOKEN    = '<long random token, same as in the Kibana connector>'
$env:SOAR_HMAC_KEY = '<long random key for signed requests>'

# 3. Start in alert-only mode first, then for real
.\Invoke-SoarListener.ps1 -WhatIfMode
.\Invoke-SoarListener.ps1 -ProtectedAccounts 'Administrator','krbtgt','adm.protected'
```

## Lab validation

| Test | Request | Listener decision |
|---|---|---|
| Authentication | POST without signature or token | `REJECTED` |
| Protect-list | Signed POST targeting an admin account | `BLOCKED` |
| Legitimate action | Signed POST targeting `test.soar` | `ACTION`: account disabled |
| Idempotency | Same request replayed | `IGNORED`: already disabled |

End to end, two attacks replayed from Kali disabled the targeted account with no human action, **in under a minute**:

| Technique | Event | Attack command | Result |
|---|---|---|---|
| AS-REP Roasting (T1558.004) | 4768 | `impacket-GetNPUsers` | `user.asrep` enabled → disabled |
| Kerberoasting (T1558.003) | 4769 | `impacket-GetUserSPNs` | `user.kerb` enabled → disabled |

## Why HMAC *and* a token?

HMAC-SHA256 signs the request body: the strongest option, validated manually with `Test-SoarGuardrails.ps1`. But Kibana builds the webhook body on the fly and cannot compute an HMAC over it, so the automated flow uses a shared token in a header, the same model commercial SOAR platforms use (bearer token / API key). The listener accepts both.

## Production checklist

- [ ] TLS in front of the listener (reverse proxy or `https://` prefix with a certificate)
- [ ] Firewall: port open to the SIEM's IP only
- [ ] Run as a dedicated service account with only the right to disable users in the target OUs
- [ ] Start with `-WhatIfMode` and review decisions for a few weeks
- [ ] Wire only high-fidelity rules, never threshold or behavioural rules
