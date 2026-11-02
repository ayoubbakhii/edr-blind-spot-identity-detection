# Wiring Kibana to the SOAR listener

## 1. Create the connector

**Stack Management → Connectors → Create connector → Webhook**

| Setting | Value |
|---|---|
| Name | `SOAR - Disable AD Account` |
| Method | `POST` |
| URL | `http://192.168.56.20:8888/` |
| Authentication | None (the token travels in a header) |
| Headers | `Content-Type: application/json` and `X-Auth-Token: <same value as $env:SOAR_TOKEN>` |

Use the built-in **Test** tab: a successful test confirms Kibana can reach the listener through the host-only network and the Windows firewall.

## 2. Attach it to the high-fidelity rules only

Attach the connector to:

- ✅ AS-REP Roasting
- ✅ Kerberoasting (RC4)
- ✅ Honeypot `svc_sqladmin`
- ❌ **Not** to Password Spraying: a threshold rule can fire on false positives, and an attacker could abuse it to lock out legitimate users.

Action frequency: **For each alert** (one call per targeted account, not one summary per rule run).

## 3. Action body

The body injects the account name from the alert's source event:

```json
{ "user": "{{#context.alerts}}{{winlog.event_data.TargetUserName}}{{/context.alerts}}" }
```

> Mustache variable paths differ slightly between Kibana versions and action frequencies. Use the **Add variable** button in the action editor to confirm the exact path for `TargetUserName` in your version.

`TargetUserName` comes as `user` on event 4768 but as `user@LAB.LOCAL` on event 4769. The listener strips the suffix, so both work.
