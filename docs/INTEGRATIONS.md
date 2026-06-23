# Enterprise Integrations

Every Cognis Neural Suite tool is built to drop into an existing enterprise stack.
This guide lists the supported integration surfaces. Where a surface is marked
*planned*, the interface exists and contributions are welcome (see CONTRIBUTING.md).

## Integration surfaces

| Surface | How | Status |
|---|---|---|
| **CLI / exit codes** | `--fail-on <severity>` for CI gates; JSON on stdout | ✅ |
| **JSON / SARIF** | machine-readable findings; SARIF for code-scanning | ✅ |
| **MCP server** | `<tool> mcp` exposes capabilities to agents/Cognis.Studio | ✅ |
| **REST / Webhooks** | `integrations/webhook.py` posts findings to any endpoint | ✅ |
| **Identity — SSO** | SAML 2.0 / OIDC (Okta, Entra ID, Auth0, Google, Ping) | planned |
| **Identity — SCIM** | user/group provisioning | planned |
| **SIEM** | Splunk HEC, Microsoft Sentinel, Elastic, Chronicle, Datadog | planned |
| **Ticketing** | Jira, ServiceNow, Linear, GitHub/GitLab Issues | planned |
| **ChatOps** | Slack, Microsoft Teams, Discord, PagerDuty | planned |
| **Cloud** | AWS, Azure, GCP (read-only roles, EventBridge/PubSub) | planned |
| **Data** | S3/GCS/Azure Blob, Postgres, Snowflake, BigQuery, Kafka | planned |
| **Secrets** | Vault, AWS/Azure/GCP secret managers, 1Password | planned |
| **GRC** | export to the Cognis compliance tools (soc2box, frameworkmap) | ✅ |

## Quick examples

Global flags (`--format`, `--fail-on`) precede the subcommand; output goes to stdout.

```bash
# CI gate (GitHub Actions, GitLab CI, Jenkins, etc.)
binhunt --format sarif --fail-on high scan ./client.exe > results.sarif

# Stream findings to a webhook / SIEM forwarder
binhunt --format json scan ./client.exe | python integrations/webhook.py --url "$COGNIS_WEBHOOK_URL"

# Forward to STIX/MISP/Sigma/Splunk/Slack via cognis-connect (optional [connect] extra)
binhunt --format json scan ./client.exe | binhunt-emit --to sigma

# Use from an AI agent over MCP
binhunt mcp
```

## Configuration

Integrations read from environment variables (12-factor) or `cognis.toml`:

```toml
[integrations.siem]
type = "splunk"          # splunk | sentinel | elastic | datadog
endpoint = "https://hec.example.com:8088"
token = "env:COGNIS_SIEM_TOKEN"

[integrations.ticketing]
type = "jira"
project = "SEC"
```

See `integrations/` for adapter stubs you can extend.
