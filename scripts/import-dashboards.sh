#!/usr/bin/env bash
# Import Kibana data views and dashboards.
#
# Runs after bootstrap-elasticsearch.sh: a data view whose index pattern
# matches nothing still imports, but every panel on it renders an error until
# data arrives, which makes a successful import look broken.
set -euo pipefail

KB="${KIBANA_URL:-http://localhost:5601}"
AUTH="${ELASTIC_USER:-elastic}:${ELASTIC_PASSWORD:-changeme-local-only}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NDJSON="$HERE/kibana/dashboards/sentinel-dashboards.ndjson"

[[ -f "$NDJSON" ]] || { echo "missing $NDJSON" >&2; exit 1; }

echo "Waiting for Kibana at ${KB}..."
for i in $(seq 1 60); do
  curl -sf "${KB}/api/status" 2>/dev/null | grep -q '"level":"available"' && break
  [[ $i -eq 60 ]] && { echo "timed out waiting for Kibana" >&2; exit 1; }
  sleep 5
done

echo "Importing saved objects..."
# overwrite=true makes this idempotent, so CI can re-run it on every merge and
# a dashboard edited by hand in the UI is reset to what is in git. That is the
# intended behaviour: git is the source of truth for dashboards too.
resp=$(curl -sS -u "$AUTH" \
  -X POST "${KB}/api/saved_objects/_import?overwrite=true" \
  -H 'kbn-xsrf: true' \
  --form file=@"${NDJSON}" \
  -w '\n%{http_code}')

code=$(tail -n1 <<<"$resp")
body=$(sed '$d' <<<"$resp")

if [[ ! "$code" =~ ^2 ]]; then
  echo "Import failed (HTTP $code):" >&2
  echo "$body" >&2
  exit 1
fi

if command -v jq >/dev/null; then
  success=$(jq -r '.success' <<<"$body")
  count=$(jq -r '.successCount' <<<"$body")
  echo "  imported: $count objects (success=$success)"
  if [[ "$success" != "true" ]]; then
    echo "  errors:" >&2
    jq -r '.errors[]? | "    \(.type)/\(.id): \(.error.type) \(.error.reason // "")"' <<<"$body" >&2
    exit 1
  fi
else
  echo "$body"
fi

echo
echo "Dashboards:"
echo "  ${KB}/app/dashboards#/view/sentinel-security-overview"
echo "  ${KB}/app/dashboards#/view/sentinel-operational-overview"
