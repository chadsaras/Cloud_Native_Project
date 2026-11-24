#!/usr/bin/env bash
# Start a local multi-node testnet without Docker.
#
# Exists because the full Compose stack needs 6GB of RAM for Elasticsearch,
# and the blockchain half of this project is worth being able to run and
# demonstrate on its own. Logs land as JSONL files that
# tests/simulate_detections.py can evaluate directly, so the entire detection
# path is exercisable with nothing but Python.
set -euo pipefail

NODES="${NODES:-3}"
VALIDATORS="${VALIDATORS:-6}"
SLOT_SECONDS="${SLOT_SECONDS:-2}"
SLOTS_PER_EPOCH="${SLOTS_PER_EPOCH:-4}"
LOG_DIR="${LOG_DIR:-./testnet-logs}"
SEED="${VALIDATOR_SEED:-sentinel-testnet}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_DIR="$HERE/blockchain-node"

# One genesis time for every node. Without this each node falls back to the
# top of the current hour, which agrees in the normal case but not across an
# hour boundary - and a testnet that silently fails to agree wastes an
# afternoon.
GENESIS_TIME="${GENESIS_TIME:-$(date +%s)}"

# Resolve to an absolute path so a relative or absolute LOG_DIR both work
# (the nodes are started from a different directory).
mkdir -p "$LOG_DIR"
LOG_DIR="$(cd "$LOG_DIR" && pwd)"
rm -f "$LOG_DIR"/*.log

echo "Starting $NODES nodes, $VALIDATORS validators, ${SLOT_SECONDS}s slots"
echo "  genesis=$GENESIS_TIME  logs=$LOG_DIR"
echo

per_node=$(( VALIDATORS / NODES ))
pids=()

for i in $(seq 0 $(( NODES - 1 ))); do
  first=$(( i * per_node ))
  last=$(( first + per_node - 1 ))
  # Built with a loop rather than `seq -s,` because BSD seq (macOS) appends a
  # trailing separator, producing "0,1," instead of "0,1".
  indices=""
  for v in $(seq "$first" "$last"); do
    indices="${indices:+$indices,}$v"
  done

  rpc_port=$(( 8545 + i ))
  p2p_port=$(( 30303 + i ))

  boot=""
  if [[ $i -gt 0 ]]; then
    boot="http://localhost:30303"
  fi

  ( cd "$NODE_DIR" && \
    NODE_ID="node-$i" \
    RPC_PORT="$rpc_port" \
    P2P_PORT="$p2p_port" \
    SELF_URL="http://localhost:$p2p_port" \
    VALIDATOR_COUNT="$VALIDATORS" \
    VALIDATOR_INDICES="$indices" \
    VALIDATOR_SEED="$SEED" \
    GENESIS_TIME="$GENESIS_TIME" \
    SLOT_SECONDS="$SLOT_SECONDS" \
    SLOTS_PER_EPOCH="$SLOTS_PER_EPOCH" \
    BOOTNODES="$boot" \
    LOG_LEVEL="${LOG_LEVEL:-INFO}" \
    python3 -m node.main > "$LOG_DIR/node-$i.log" 2>&1 ) &

  pids+=($!)
  echo "  node-$i  validators=[$indices]  rpc=:$rpc_port  p2p=:$p2p_port"
done

echo
echo "waiting for nodes to come up..."
for i in $(seq 0 $(( NODES - 1 ))); do
  rpc_port=$(( 8545 + i ))
  for _ in $(seq 1 30); do
    if curl -sf "http://localhost:$rpc_port/healthz" >/dev/null 2>&1; then
      echo "  node-$i ready"
      break
    fi
    sleep 1
  done
done

echo
echo "Testnet is up."
echo "  status:   curl -s http://localhost:8545/status | python3 -m json.tool"
echo "  attack:   python3 scripts/blockchain_attacks.py --scenario all"
echo "  evaluate: python3 tests/simulate_detections.py $LOG_DIR/node-0.log"
echo
echo "Press Ctrl-C to stop."

cleanup() {
  echo
  echo "stopping nodes..."
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  echo "stopped. logs remain in $LOG_DIR/"
}
trap cleanup EXIT INT TERM

wait
