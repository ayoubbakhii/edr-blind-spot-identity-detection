# Lessons learned

Real problems hit while building the chain, and how they were solved.

## 1. Validate the field before writing the rule

Before writing each detection rule, I inspected a real attack event in Kibana **Discover** to confirm the exact field path and format. This prevented silent rules:

- `winlog.event_data.TicketEncryptionType` is stored as a **hex string** (`"0x17"` for RC4, `"0x12"` for AES), not an integer.
- The attacker IP changes format by event type: `::ffff:192.168.56.x` on Kerberos events, but `192.168.56.x` (no prefix) on NTLM logons (4624).

## 2. The Kerberoasting response failed silently at first

Event 4768 returns `TargetUserName` **without** a domain suffix (`user.asrep`), while event 4769 returns it **with** one (`user.kerb@LAB.LOCAL`). `Disable-ADAccount` does not accept the second form, so the first Kerberoasting chain did nothing.

**Fix:** normalise the account name in the listener by stripping the suffix:

```powershell
$account = ($json.user -split '@')[0]
```

## 3. Ghost http.sys reservations on the listener port

Restarting the PowerShell listener often failed with *"Failed to listen on prefix http://+:8888/ because it conflicts with an existing registration"*: `Ctrl+C` does not immediately release the kernel-level URL reservation held by the old PowerShell process.

| Symptom | Root cause | Fix |
|---|---|---|
| Port 8888 busy on restart | http.sys session held by an old PowerShell process | `Get-Process powershell`, stop the oldest one, check `netsh http show servicestate` |
| Conflict persists after several attempts | Several stacked http.sys sessions | Reboot the DC VM |

**Practice adopted:** keep a single listener window, let http.sys release the port before restarting, and reboot after two failures.

## 4. HMAC vs static token

HMAC-SHA256 over the request body is the strongest option, and the listener supports it (validated manually). But Kibana builds the webhook body dynamically (it injects the account name from the alert) and cannot compute an HMAC over that variable body. The automated flow therefore uses a **shared token in a header**, the same model commercial SOAR platforms use when calling a response endpoint (bearer token or API key). The listener accepts both.

## 5. Only automate on high-fidelity rules

Automating a response on a rule that can produce false positives hands the attacker a lever: trigger the alert on purpose, and legitimate accounts get disabled. The webhook is attached to AS-REP Roasting, Kerberoasting and the honeypot, **never** to the threshold-based spraying rule. Knowing the difference between "what we detect" and "what we act on automatically" is the core of a mature response design.
