# Lab setup

## Design goals

- **Realism:** a representative Active Directory domain.
- **Reproducibility:** replay the exact same attacks before and after adding the SIEM.
- **Isolation:** keep offensive actions contained.
- **Low cost:** free tools and evaluation licences only.

VirtualBox was chosen for its flexible internal networking. Versions were frozen so experiments stay reproducible.

## Architecture

| VM | Role | OS | IP (host-only) |
|---|---|---|---|
| VM1 | Kaspersky Security Center (EDR management) | Ubuntu Server 22.04 LTS | 192.168.56.10 |
| VM2 | Active Directory domain controller (`lab.local`: AD DS, DNS, KDC) + EDR agent | Windows Server 2022 Standard (Desktop Experience) | 192.168.56.20 |
| VM3 | Attacker | Kali Linux | 192.168.56.30 |
| VM4 | Elastic Stack (Elasticsearch + Kibana, Docker) | Ubuntu Server 22.04 LTS | 192.168.56.40 |

## Network

Each VM has two network adapters:

1. **NAT**: internet access during installation (packages, updates).
2. **Host-only** (`192.168.56.0/24`): isolates the test bench from the real network, with static IPs so the EDR agent always finds its management server.

## Why Kaspersky for the EDR lab?

The client's production EDR is Trend Micro. Trend Micro Apex One's server, however, is Windows-only (IIS + SQL Server), which would have required an extra Windows Server VM just for management. Kaspersky Security Center installs natively on Ubuntu 22.04, has free public documentation, a fully functional evaluation licence (Kaspersky Next EDR Foundations) and native MITRE ATT&CK mapping in its console.

The finding is about **EDRs as a category** (endpoint sensors do not see Kerberos abuse), so it transfers to the production EDR.

## Elastic Stack

- Elasticsearch + Kibana **9.4.2** with Docker Compose: see [`../config/docker-compose.yml`](../config/docker-compose.yml).
- Security must be enabled (`xpack.security.enabled=true`): it's a prerequisite for the Kibana detection engine.
- **Winlogbeat 9.4.2** on the DC, version-matched to the stack: see [`../config/winlogbeat.yml`](../config/winlogbeat.yml).
- All machines normalised to **UTC**, so Kibana alerts and EDR console events can be compared on the same timeline.

## Audit policy on the DC

Make sure these are enabled (Advanced Audit Policy) so the events exist in the first place:

- Account Logon → **Audit Kerberos Authentication Service** (4768) and **Audit Kerberos Service Ticket Operations** (4769): Success and Failure.
- Logon/Logoff → **Audit Logon** (4624, 4625): Success and Failure.

## Lab accounts (placeholders)

| Account | Purpose |
|---|---|
| `user.asrep` | Pre-authentication disabled, AS-REP Roasting target |
| `user.kerb` | Standard user used to request service tickets |
| `svc_sqladmin` | Honeypot service account with an MSSQL SPN |
| `test.soar` | Test account for SOAR guardrail validation |
| `adm.protected` | Admin account on the SOAR protect-list |
