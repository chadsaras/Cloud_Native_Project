#!/usr/bin/env bash
# Install the detection rules from kibana/detections/detection-rules.json into
# the Kibana Detection Engine.
#
# Idempotent: rules are keyed by rule_id, so re-running updates in place rather
# than creating duplicates. That is what makes this safe to run from CI on
# every merge to main.
set -euo pipefail

KB="${KIBANA_URL:-http://localhost:5601}"
AUTH="${ELASTIC_USER:-elastic}:${ELASTIC_PASSWORD:-changeme-local-only}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="$HERE/kibana/detections/detection-rules.json"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

echo "Waiting for Kibana at ${KB}..."
for i in $(seq 1 60); do
  if curl -sf "${KB}/api/status" 2>/dev/null | grep -q '"level":"available"'; then
    echo "  kibana is up"; break
  fi
  [[ $i -eq 60 ]] && { echo "timed out waiting for Kibana" >&2; exit 1; }
  sleep 5
done

installed=0; failed=0

# Read rule ids into an array first so the loop body is not in a subshell -
# otherwise the counters reset and the script always reports zero.
#
# `mapfile` would be the obvious way to do this, but it is bash 4+ and macOS
# still ships bash 3.2, so this uses a portable read loop instead.
rule_ids=()
while IFS= read -r line; do
  [[ -n "$line" ]] && rule_ids+=("$line")
done < <(jq -r '.rules[].rule_id' "$RULES")

for rid in "${rule_ids[@]}"; do
  # Translate our rule format into the Detection Engine's schema. Keeping our
  # own shape and converting here means the rule files stay readable and are
  # not hostage to the API's schema changing between Kibana versions.
  payload=$(jq -c --arg rid "$rid" '
    .rules[] | select(.rule_id == $rid) |
    {
      rule_id:      .rule_id,
      name:         .name,
      description:  .description,
      risk_score:   .risk_score,
      severity:     .severity,
      type:         .type,
      index:        .index,
      language:     .language,
      query:        .query,
      interval:     .interval,
      from:         .from,
      enabled:      true,
      tags:         (["sentinel-platform"] + [(.rule_id | split("-")[0])]),
      false_positives: (.false_positives // []),
      # Kibana requires a reference URL on every tactic/technique/subtechnique;
      # they are fully determined by the ids, so derive rather than store them.
      threat:       ((.threat // []) | map(
                       .tactic.reference = "https://attack.mitre.org/tactics/\(.tactic.id)/"
                       | .technique |= map(
                           .reference = "https://attack.mitre.org/techniques/\(.id)/"
                           | if .subtechnique then .subtechnique |= map(
                               .reference = "https://attack.mitre.org/techniques/\(.id | sub("\\."; "/"))/")
                             else . end))),
      note:         ((.investigation_steps // []) | to_entries | map("\(.key+1). \(.value)") | join("\n"))
    }
    + (if .threshold then {threshold: .threshold} else {} end)
  ' "$RULES")

  name=$(jq -r --arg rid "$rid" '.rules[] | select(.rule_id==$rid) | .name' "$RULES")

  # Kibana has no upsert: POST creates (409 if the rule_id exists) and PUT only
  # updates (404 if it does not). Create first, fall back to update on 409.
  send() {
    curl -sS -u "$AUTH" -X "$1" "${KB}/api/detection_engine/rules" \
      -H 'Content-Type: application/json' -H 'kbn-xsrf: true' \
      -d "$payload" -w '\n%{http_code}'
  }
  resp=$(send POST)
  code=$(tail -n1 <<<"$resp")
  if [[ "$code" == "409" ]]; then
    resp=$(send PUT)
    code=$(tail -n1 <<<"$resp")
  fi
  body=$(sed '$d' <<<"$resp")

  if [[ "$code" =~ ^2 ]]; then
    printf '  ok    %-9s %s\n' "$rid" "$name"
    installed=$((installed+1))
  else
    printf '  FAIL  %-9s %s (HTTP %s)\n        %s\n' "$rid" "$name" "$code" \
      "$(jq -rc '.message // .error // .' <<<"$body" 2>/dev/null || echo "$body")" >&2
    failed=$((failed+1))
  fi
done

echo
echo "Installed/updated: $installed    Failed: $failed"

if [[ $failed -gt 0 ]]; then
  cat >&2 <<'NOTE'

Note: OPS-002 (pipeline heartbeat) is an absence-of-signal rule. The Detection
Engine cannot express "alert when count is zero" as a query, so if it failed
above it must be created in Kibana as a threshold rule with the condition
inverted, or replaced with an Elasticsearch Watcher. This is a genuine
limitation of the rule type, not a bug in this script.
NOTE
  exit 1
fi
