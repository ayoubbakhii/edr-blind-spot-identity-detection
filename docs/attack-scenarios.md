# Attack scenarios

All attacks were run from the Kali VM (`192.168.56.30`) against the lab domain `lab.local` (DC: `192.168.56.20`), in an isolated host-only network. Account names below are lab placeholders.

The campaign was run **twice under identical conditions**: first with the EDR alone, then with the SIEM/SOAR chain in place. Keeping conditions identical is what makes the before/after comparison valid.

## Family 1: host-based ("host-loud") attacks, blocked by the EDR

These attacks materialise on the endpoint (a file on disk, a script in memory, a binary executed), which is exactly where an EDR sensor looks.

| # | Scenario | MITRE | What was done | EDR verdict |
|---|---|---|---|---|
| 1 | EICAR | Test | Standard inert anti-malware test file written to disk | Blocked (`EICAR-Test-File`) |
| 2 | AMSI | T1059.001 | EICAR test string evaluated in PowerShell memory (fileless) | Blocked (AMSI) |
| 3 | Mimikatz | T1003.001 | Credential-dumping tool downloaded to the endpoint | Blocked (`HEUR:Trojan.Win32.Generic`) |
| 4 | Meterpreter | T1204 / T1055 | Reverse-shell payload delivered over HTTP | Blocked (`HEUR:Trojan.Win32.Generic`) |
| 5 | PsExec | T1021.002 / T1569.002 | Remote service execution with `impacket-psexec` | Blocked (`HackTool.Win32.Remoxec`) |
| 6 | NetExec | T1570 / T1059 | File upload + remote execution over SMB with `nxc` | Blocked (`Trojan.Win64.Shelma.b`) |

**Result: 6/6 blocked.**

## Family 2: identity attacks, invisible to the EDR

These attacks only use legitimate Kerberos/NTLM exchanges with the domain controller. No binary touches the target, so the EDR has nothing to inspect.

### 7. Domain account enumeration (T1087.002)

Kerbrute asks the KDC whether usernames exist, without ever trying a password.

```bash
kerbrute userenum -d lab.local --dc 192.168.56.20 users.txt
```

- **Log trace:** event 4768 (TGT requests) on the DC.
- **EDR alone:** silent. **SIEM:** detected through the volume pattern of the spraying/enumeration rule.

### 8. Password spraying (T1110.003)

One common password tried against many accounts, which stays under per-account lockout thresholds.

```bash
nxc smb 192.168.56.20 -u users.txt -p '<common-password>' --continue-on-success
```

- **Log trace:** events 4625 (failures) and 4624 (success), one source IP hitting many accounts.
- **EDR alone:** silent. **SIEM:** threshold rule fires at ≥ 3 distinct accounts per source IP.

### 9. AS-REP Roasting (T1558.004)

Accounts without Kerberos pre-authentication return an AS-REP encrypted with the user's key, which can be cracked offline.

```bash
impacket-GetNPUsers lab.local/ -dc-ip 192.168.56.20 -usersfile users.txt -no-pass
```

- **Log trace:** event 4768 with `PreAuthType = 0`.
- **EDR alone:** silent. **SIEM:** High alert within a minute. **SOAR:** account disabled automatically.

### 10. Kerberoasting (T1558.003)

Any domain user can request a service ticket for an SPN; the ticket is encrypted with the service account's key and can be cracked offline. Attackers force RC4 to make cracking easier.

```bash
impacket-GetUserSPNs lab.local/<user>:'<password>' -dc-ip 192.168.56.20 -request
```

- **Log trace:** event 4769 with `TicketEncryptionType = 0x17` (RC4); legitimate modern traffic uses AES (`0x12`).
- **EDR alone:** silent. **SIEM:** High alert (generic RC4 rule + honeypot rule). **SOAR:** requesting account disabled automatically.

**Result: 0/4 seen by the EDR → 4/4 detected by the SIEM.**
