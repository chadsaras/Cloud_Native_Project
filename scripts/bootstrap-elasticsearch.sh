#!/usr/bin/env bash
# Install index templates and ILM policies.
#
# Order matters and is the reason this is a script rather than a README step:
# ILM policies must exist before the index template that references them, and
# the component templates must exist before the composed template that
# includes them. Applying these out of order fails with an error that does not
# say "wrong order".
set -euo pipefail

ES="${ELASTICSEARCH_URL:-http://localhost:9200}"
AUTH="${ELASTIC_USER:-elastic}:${ELASTIC_PASSWORD:-changeme-local-only}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

curl_es() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -u "$AUTH" -X "$method" "${ES}${path}" -H 'Content-Type: application/json' -w '\n%{http_code}')
  [[ -n "$body" ]] && args+=(-d "$body")
  curl "${args[@]}"
}

check() {
  local desc="$1" out="$2"
  local code; code=$(tail -n1 <<<"$out")
  local body; body=$(sed '$d' <<<"$out")
  if [[ "$code" =~ ^2 ]]; then
    printf '  ok    %s\n' "$desc"
  else
    printf '  FAIL  %s (HTTP %s)\n    %s\n' "$desc" "$code" "$body" >&2
    return 1
  fi
}

echo "Waiting for Elasticsearch at ${ES}..."
for i in $(seq 1 60); do
  if curl -sf -u "$AUTH" "${ES}/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null 2>&1; then
    echo "  cluster is up"; break
  fi
  [[ $i -eq 60 ]] && { echo "timed out waiting for Elasticsearch" >&2; exit 1; }
  sleep 5
done

echo
echo "Installing ILM policies..."
# Each top-level key in ilm-policies.json is a policy name; the value is the
# body. jq splits them out so the file stays readable as one document.
for name in $(jq -r 'keys[]' "$HERE/logstash/templates/ilm-policies.json"); do
  body=$(jq -c --arg n "$name" '.[$n] | {policy}' "$HERE/logstash/templates/ilm-policies.json")
  check "ilm/$name" "$(curl_es PUT "/_ilm/policy/${name}" "$body")"
done

echo
echo "Installing component templates..."
check "component/sentinel-logs-mappings" \
  "$(curl_es PUT "/_component_template/sentinel-logs-mappings" "$(jq -c . "$HERE/logstash/templates/component-logs-mappings.json")")"
check "component/sentinel-logs-settings" \
  "$(curl_es PUT "/_component_template/sentinel-logs-settings" "$(jq -c . "$HERE/logstash/templates/component-logs-settings.json")")"

echo
echo "Installing index templates..."

# Security datasets -> 90 day retention.
check "template/logs-security" "$(curl_es PUT "/_index_template/logs-security" '{
  "index_patterns": ["logs-app.auth-*","logs-app.iam-*","logs-app.waf-*","logs-app.data-*","logs-blockchain.consensus-*","logs-blockchain.rpc-*","logs-blockchain.p2p-*"],
  "data_stream": {},
  "priority": 500,
  "composed_of": ["sentinel-logs-mappings","sentinel-logs-settings"],
  "template": { "settings": { "index.lifecycle.name": "logs-security-retention" } },
  "_meta": { "managed_by": "sentinel-platform", "retention": "90d" }
}')"

# Operational datasets -> 14 day retention.
check "template/logs-operational" "$(curl_es PUT "/_index_template/logs-operational" '{
  "index_patterns": ["logs-nginx.access-*","logs-app.checkout-*","logs-app.performance-*","logs-kubernetes.*","logs-blockchain.mempool-*"],
  "data_stream": {},
  "priority": 400,
  "composed_of": ["sentinel-logs-mappings","sentinel-logs-settings"],
  "template": { "settings": { "index.lifecycle.name": "logs-operational-retention" } },
  "_meta": { "managed_by": "sentinel-platform", "retention": "14d" }
}')"

# Unparsed -> 3 days. Highest priority so it wins over the broader patterns.
check "template/logs-unparsed" "$(curl_es PUT "/_index_template/logs-unparsed" '{
  "index_patterns": ["logs-platform.unparsed-*"],
  "data_stream": {},
  "priority": 600,
  "composed_of": ["sentinel-logs-mappings","sentinel-logs-settings"],
  "template": { "settings": { "index.lifecycle.name": "logs-unparsed-retention" } },
  "_meta": { "managed_by": "sentinel-platform", "retention": "3d" }
}')"

# Catch-all so a new dataset never lands with dynamic mapping enabled. Lowest
# priority, so any specific template above beats it.
check "template/logs-catchall" "$(curl_es PUT "/_index_template/logs-catchall" '{
  "index_patterns": ["logs-*"],
  "data_stream": {},
  "priority": 101,
  "composed_of": ["sentinel-logs-mappings","sentinel-logs-settings"],
  "template": { "settings": { "index.lifecycle.name": "logs-operational-retention" } },
  "_meta": { "managed_by": "sentinel-platform", "note": "fallback for unanticipated datasets" }
}')"

check "template/metrics-heartbeat" "$(curl_es PUT "/_index_template/metrics-heartbeat" '{
  "index_patterns": ["metrics-logstash.heartbeat-*"],
  "data_stream": {},
  "priority": 500,
  "template": { "settings": { "index.lifecycle.name": "logs-unparsed-retention", "number_of_shards": 1, "number_of_replicas": 0 } },
  "_meta": { "managed_by": "sentinel-platform" }
}')"

echo
echo "Bootstrap complete."
echo "Verify with:  curl -u $AUTH '${ES}/_index_template/logs-*?pretty'"
