# Detection rules

## Kibana (tested in the lab)

All four rules share the same settings: run every minute, severity **High**, risk score **73**, explicit MITRE ATT&CK mapping. Index pattern: `winlogbeat-*`.

| File | Type | Query | MITRE | Auto-response |
|---|---|---|---|---|
| [`asrep-roasting.json`](kibana/asrep-roasting.json) | Query | `event.code: "4768" and winlog.event_data.PreAuthType: "0"` | T1558.004 | ✅ |
| [`kerberoasting-rc4.json`](kibana/kerberoasting-rc4.json) | Query | `event.code: "4769" and winlog.event_data.TicketEncryptionType: "0x17"` | T1558.003 | ✅ |
| [`password-spraying-threshold.json`](kibana/password-spraying-threshold.json) | Threshold | `event.code: "4624" and winlog.event_data.LogonType: "3"`, grouped by source IP, cardinality(`TargetUserName`) ≥ 3 | T1110.003 | ❌ alert only |
| [`honeypot-svc-sqladmin.json`](kibana/honeypot-svc-sqladmin.json) | Query | `event.code: "4769" and winlog.event_data.ServiceName: "svc_sqladmin"` | T1558.003 | ✅ |

### Why each rule works

- **AS-REP Roasting:** almost a single-event signature. A TGT request without pre-authentication is abnormal; a healthy domain practically never produces one.
- **Kerberoasting:** event 4769 is noisy (every legitimate service access creates one). The discriminating signal is **RC4 encryption**, which attackers force to make cracking easier. This is why a rules-based SIEM beats a simple single-event alert here.
- **Password spraying:** a DC produces logons constantly, so volume alone means nothing. The pattern that matters is **one source IP authenticating to many distinct accounts** in a short time.
- **Honeypot:** filters on the account identity rather than on encryption. Nothing legitimate requests a ticket for `svc_sqladmin`, which makes it the ideal trigger for automated response.

### Importing

In Kibana: **Security → Rules → Detection rules (SIEM) → Import rules**. The import expects `.ndjson`; convert with:

```bash
for f in kibana/*.json; do jq -c . "$f"; done > rules.ndjson
```

Or create each rule through the API:

```bash
curl -u elastic:$ELASTIC_PASSWORD -X POST "http://localhost:5601/api/detection_engine/rules" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d @kibana/asrep-roasting.json
```

## Microsoft Sentinel (translations)

The [`sentinel/`](sentinel/) folder translates the same detection logic into **KQL** for the `SecurityEvent` table. These translations were written after the lab, as SC-200 practice, and **were not run in the lab**. Validate them in your own workspace before use.
