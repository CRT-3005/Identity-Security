# Filebeat Troubleshooting (Wazuh AIO)

This page documents how I fixed Filebeat when it was not shipping Wazuh alerts to the Indexer in my all-in-one Wazuh lab (Ubuntu Manager + Indexer + Dashboard on the same host).

## Objective

Get Filebeat reliably reading `/var/ossec/logs/alerts/alerts.json` and sending documents to the local OpenSearch endpoint (on Wazuh AIO). Confirm data is visible in the Wazuh Dashboard (Discover).

## Symptoms Observed

- `systemctl status filebeat` shows `failed (code=exited, status=2)` (usually a YAML error), or service runs but Discover shows no results.
- Filebeat logs do not show a stable connection to `https://127.0.0.1:9200`.
- No message like `Harvester started for file: /var/ossec/logs/alerts/alerts.json`.

## Quick Health Checks

```bash
# Service and recent logs
systemctl status filebeat --no-pager
journalctl -u filebeat -e --no-pager

# Validate configuration and output connectivity
sudo filebeat test config -e
sudo filebeat test output -e

# Ensure the manager is producing alerts to ship
sudo tail -n 50 /var/ossec/logs/alerts/alerts.json
```

## Minimal Working Configuration (pick ONE output)

Wazuh all-in-one typically installs Filebeat 7.10.x (OSS). For this build, use `output.elasticsearch` to talk to the local OpenSearch endpoint. If you are using a newer Filebeat that supports it, you may instead use `output.opensearch`.

Edit `/etc/filebeat/filebeat.yml` to the following minimal configuration:

```yaml
filebeat.inputs:
  - type: filestream
    id: wazuh-alerts
    enabled: true
    paths:
      - /var/ossec/logs/alerts/alerts.json
    parsers:
      - ndjson:
          target: ""              # keep fields at root
          add_error_key: true

# -------- CHOOSE ONE OUTPUT --------

# A) Wazuh AIO / Filebeat 7.10.x (recommended on AIO)
output.elasticsearch:
  hosts: ["https://127.0.0.1:9200"]
  username: "admin"
  password: "admin"
  ssl.verification_mode: none
  protocol: "https"

# B) Newer Filebeat with native OpenSearch output (comment A, uncomment B)
# output.opensearch:
#   hosts: ["https://127.0.0.1:9200"]
#   username: "admin"
#   password: "admin"
#   ssl.verification_mode: none
#   protocol: "https"

setup.template.enabled: true
setup.ilm.enabled: false
```

Notes:
- The `ndjson` parser is required because `alerts.json` is one JSON object per line.
- `ssl.verification_mode: none` is acceptable for a lab with self-signed certificates.

## Apply and Verify

```bash
# Check YAML before restarting
sudo filebeat test config -e

# Restart and watch for success
sudo systemctl restart filebeat
journalctl -u filebeat -e --no-pager
```

Expected messages:
- `Harvester started for file: /var/ossec/logs/alerts/alerts.json`
- `Attempting to connect to Elasticsearch version 7.10.2`
- `Connection to backoff(elasticsearch(https://127.0.0.1:9200)) established`

## Index and Ingest Sanity Checks

```bash
# Cluster health
curl -sk -u admin:admin 'https://127.0.0.1:9200/_cluster/health?pretty'

# Do Wazuh indices exist?
curl -sk -u admin:admin 'https://127.0.0.1:9200/_cat/indices?v' | grep wazuh

# Are documents arriving?
curl -sk -u admin:admin 'https://127.0.0.1:9200/wazuh-alerts-*/_count?pretty'
```

In Wazuh Dashboard -> Discover, use the index pattern `wazuh-alerts-*`.

## Common Issues and Fixes

- Exit code 2 (YAML): whitespace/indent problems. Replace with the minimal config above and run `filebeat test config -e`.
- Wrong output stanza: `output.opensearch` is not supported on Filebeat 7.10.x. Use `output.elasticsearch` on AIO.
- Self-signed TLS: set `ssl.verification_mode: none` for the lab.
- Stuck registry after rotation (lab reset):
  ```bash
  sudo systemctl stop filebeat
  sudo rm -rf /var/lib/filebeat/registry
  sudo systemctl start filebeat
  ```
- No alerts to ship: if `alerts.json` is not growing, the manager is not generating alerts (see smoke test below).
- Permissions: ensure Filebeat can read `/var/ossec/logs/alerts/alerts.json` (usually fine on AIO; Filebeat runs as root).

## Smoke Test: Is Data Flowing?

```bash
# A) Generate an alert via wazuh-logtest (interactive)
sudo /var/ossec/bin/wazuh-logtest
# type: 1
# paste any sample line
# press Enter on a blank line, then q

# B) Or append a test JSON line (lab only)
sudo sh -c 'echo "{"test":"ping","@timestamp":"$(date -Iseconds)"}" >> /var/ossec/logs/alerts/alerts.json'

# C) Watch Filebeat logs for harvest/ship lines
journalctl -u filebeat -e --no-pager

# D) Confirm document counts increase
curl -sk -u admin:admin 'https://127.0.0.1:9200/wazuh-alerts-*/_count?pretty'
```

## Appendix: Expected Good Log Lines

From `journalctl -u filebeat -e`:
```
Harvester started for file: /var/ossec/logs/alerts/alerts.json
Connecting to backoff(elasticsearch(https://127.0.0.1:9200))
Attempting to connect to Elasticsearch version 7.10.2
Connection to backoff(elasticsearch(https://127.0.0.1:9200)) established
```

From `alerts.json` (file should be growing):
```
{"@timestamp":"...","rule":{"id":"...","description":"..."},"agent":{"id":"..."},"win":{"system":{"eventID":...}}, ...}
```
