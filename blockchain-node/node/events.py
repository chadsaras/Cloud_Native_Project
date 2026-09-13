"""ECS logging for blockchain node events.

ECS has no blockchain fields, so this defines a `blockchain.*` namespace. It is
kept as a small, explicit vocabulary rather than dumping arbitrary node state
into the log, because every field here has to be mapped in the Elasticsearch
template -- the platform runs `dynamic: false`, so an unmapped field is stored
but never indexed and any detection rule querying it silently never fires.

The field names deliberately mirror the concepts real consensus clients expose
(slot, epoch, validator index, head, reorg depth, peer id) so that a grok
parser for Lighthouse or Prysm output could target the same schema later.

Duplicated rather than imported from demo-app: this is a separate container
image with its own dependency surface, and a shared library across two images
would have to be published and versioned to be worth it.
"""

import json
import logging
import os
import socket
import sys
import time
from contextvars import ContextVar

trace_id_var: ContextVar[str] = ContextVar("trace_id", default="-")

NODE_ID = os.getenv("NODE_ID", "node-0")
CHAIN_ID = int(os.getenv("CHAIN_ID", "31337"))
SERVICE_NAME = os.getenv("SERVICE_NAME", "blockchain-node")
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "0.3.0")
SERVICE_ENV = os.getenv("SERVICE_ENV", "testnet")


class EcsJsonFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__()
        self.hostname = socket.gethostname()

    def format(self, record: logging.LogRecord) -> str:
        doc = {
            "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
                          + f".{int(record.msecs):03d}Z",
            "message": record.getMessage(),
            "log": {"level": record.levelname.lower(), "logger": record.name},
            "ecs": {"version": "8.11.0"},
            "service": {"name": SERVICE_NAME, "version": SERVICE_VERSION,
                        "environment": SERVICE_ENV, "node": {"name": NODE_ID}},
            "host": {"hostname": self.hostname},
            "blockchain": {"node_id": NODE_ID, "chain_id": CHAIN_ID},
        }
        trace_id = trace_id_var.get()
        if trace_id != "-":
            doc["trace"] = {"id": trace_id}

        extra = getattr(record, "ecs", None)
        if isinstance(extra, dict):
            _deep_merge(doc, extra)

        if record.exc_info:
            exc_type, exc_value, _ = record.exc_info
            doc["error"] = {
                "type": exc_type.__name__ if exc_type else "UnknownError",
                "message": str(exc_value),
                "stack_trace": self.formatException(record.exc_info),
            }
        return json.dumps(doc, separators=(",", ":"), default=str)


def _deep_merge(base: dict, overlay: dict) -> dict:
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def configure_logging() -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(EcsJsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    return logging.getLogger(SERVICE_NAME)


log = logging.getLogger(f"{SERVICE_NAME}.events")


# --- Consensus events -------------------------------------------------------

def block_proposed(block, duration_ms: float) -> None:
    log.info(
        "Proposed block %d at slot %d (%s)", block.height, block.slot, block.hash()[:12],
        extra={"ecs": {
            "event": {"kind": "event", "category": ["process"], "type": ["creation"],
                      "action": "block_proposed", "outcome": "success",
                      "dataset": "blockchain.consensus",
                      "duration": int(duration_ms * 1e6)},
            "blockchain": {
                "block": {"height": block.height, "hash": block.hash(),
                          "parent_hash": block.parent_hash,
                          "tx_count": len(block.transactions)},
                "slot": block.slot,
                "validator": {"index": block.proposer_index},
            },
        }},
    )


def block_imported(block, status: str, reorg_depth: int = 0) -> None:
    log.info(
        "Imported block %d from peer (%s)", block.height, status,
        extra={"ecs": {
            "event": {"kind": "event", "category": ["process"],
                      "action": "block_imported", "outcome": "success",
                      "dataset": "blockchain.consensus"},
            "blockchain": {
                "block": {"height": block.height, "hash": block.hash(),
                          "parent_hash": block.parent_hash},
                "slot": block.slot,
                "validator": {"index": block.proposer_index},
                "fork_choice": status,
                "reorg_depth": reorg_depth,
            },
        }},
    )


def block_rejected(reason: str, detail: str, peer_id: str, source_ip: str,
                   height=None) -> None:
    """An invalid block arrived from a peer.

    Logged as an alert, not an error: a peer sending blocks that fail
    validation is either running incompatible software or attacking, and both
    warrant someone looking. The `rejection_reason` keyword is what lets
    BC-008 tell those two apart.
    """
    log.warning(
        "Rejected block from peer %s: %s", peer_id, reason,
        extra={"ecs": {
            "event": {"kind": "alert", "category": ["network", "intrusion_detection"],
                      "type": ["denied"], "action": "block_rejected",
                      "outcome": "failure", "reason": reason, "severity": 55,
                      "dataset": "blockchain.consensus"},
            "blockchain": {"rejection_reason": reason,
                           "peer": {"id": peer_id},
                           "block": {"height": height} if height is not None else {}},
            "source": {"ip": source_ip},
        }},
    )


def chain_reorg(depth: int, old_head, new_head, common_ancestor: str) -> None:
    """A reorganisation: the canonical chain changed beneath us.

    Shallow reorgs of one or two blocks are normal and happen when two
    proposers produce near-simultaneously. Deep reorgs are not normal -- they
    mean either a serious network partition healing, or an attacker with
    enough stake to rewrite history. Depth is the whole signal, which is why
    BC-004 thresholds on it rather than on the event occurring.
    """
    severity = 40 if depth <= 2 else 85
    log.warning(
        "Chain reorganisation of depth %d: head %s -> %s",
        depth, old_head.hash()[:12], new_head.hash()[:12],
        extra={"ecs": {
            "event": {"kind": "alert" if depth > 2 else "event",
                      "category": ["process"], "action": "chain_reorg",
                      "outcome": "success", "severity": severity,
                      "dataset": "blockchain.consensus"},
            "blockchain": {
                "reorg_depth": depth,
                "block": {"height": new_head.height, "hash": new_head.hash()},
                "previous_head": old_head.hash(),
                "common_ancestor": common_ancestor,
                "slot": new_head.slot,
            },
        }},
    )


def slashable_offence(offence, validator) -> None:
    """A validator signed two conflicting messages for one slot.

    The single most serious event this node can emit. In production this costs
    the operator a minimum of 1 ETH immediately, removal from the validator
    set, and a correlation penalty that scales with how many other validators
    were slashed at the same time -- which is what turns one operator's
    failover mistake across a large fleet into a very expensive afternoon.
    """
    log.critical(
        "SLASHABLE OFFENCE: validator %d committed %s at slot %d",
        offence.validator_index, offence.kind, offence.slot,
        extra={"ecs": {
            "event": {"kind": "alert", "category": ["intrusion_detection", "process"],
                      "type": ["indicator"], "action": "slashable_offence",
                      "outcome": "failure", "severity": 99,
                      "reason": offence.kind,
                      "dataset": "blockchain.consensus"},
            "blockchain": {
                "slashing": {"kind": offence.kind,
                             "evidence": list(offence.evidence)},
                "validator": {"index": offence.validator_index,
                              "pubkey": validator.pubkey if validator else None},
                "slot": offence.slot,
            },
        }},
    )


def duty_missed(slot: int, validator_index: int, epoch: int) -> None:
    log.warning(
        "Validator %d missed proposal duty at slot %d", validator_index, slot,
        extra={"ecs": {
            "event": {"kind": "event", "category": ["process"],
                      "action": "duty_missed", "outcome": "failure",
                      "severity": 45, "dataset": "blockchain.consensus"},
            "blockchain": {"slot": slot, "epoch": epoch,
                           "validator": {"index": validator_index},
                           "duty": "proposal"},
        }},
    )


def attestation_recorded(attestation, support: float) -> None:
    log.debug(
        "Attestation from validator %d for slot %d",
        attestation.validator_index, attestation.slot,
        extra={"ecs": {
            "event": {"kind": "event", "category": ["process"],
                      "action": "attestation", "outcome": "success",
                      "dataset": "blockchain.consensus"},
            "blockchain": {"slot": attestation.slot,
                           "validator": {"index": attestation.validator_index},
                           "block": {"hash": attestation.block_hash},
                           "participation": round(support, 3)},
        }},
    )


def epoch_finalized(epoch: int, height: int, participation: float) -> None:
    log.info(
        "Finalized epoch %d at height %d (%.0f%% participation)",
        epoch, height, participation * 100,
        extra={"ecs": {
            "event": {"kind": "event", "category": ["process"],
                      "action": "epoch_finalized", "outcome": "success",
                      "dataset": "blockchain.consensus"},
            "blockchain": {"epoch": epoch, "block": {"height": height},
                           "participation": round(participation, 3)},
        }},
    )


def finality_stalled(epochs_behind: int, justified: int, finalized: int) -> None:
    """Finality has not advanced.

    On Ethereum this is the alarm that matters more than almost any other: if
    finality stalls for four epochs the chain enters the inactivity leak and
    begins draining stake from non-participating validators until finality
    resumes. An operator who is offline during a leak loses money continuously.
    """
    log.error(
        "Finality stalled: %d epochs without finalization", epochs_behind,
        extra={"ecs": {
            "event": {"kind": "alert", "category": ["process"],
                      "action": "finality_stalled", "outcome": "failure",
                      "severity": 88, "dataset": "blockchain.consensus"},
            "blockchain": {"epochs_behind": epochs_behind,
                           "justified_height": justified,
                           "finalized_height": finalized},
        }},
    )


# --- JSON-RPC events --------------------------------------------------------

def rpc_request(method: str, source_ip: str, duration_ms: float,
                status: int, namespace: str, param_size: int = 0) -> None:
    log.info(
        "RPC %s from %s", method, source_ip,
        extra={"ecs": {
            "event": {"kind": "event", "category": ["web"], "type": ["access"],
                      "action": "rpc_request", "dataset": "blockchain.rpc",
                      "outcome": "success" if status == 200 else "failure",
                      "duration": int(duration_ms * 1e6)},
            "blockchain": {"rpc": {"method": method, "namespace": namespace,
                                   "param_bytes": param_size}},
            "http": {"request": {"method": "POST"},
                     "response": {"status_code": status}},
            "url": {"path": "/"},
            "source": {"ip": source_ip},
        }},
    )


def rpc_unauthorized(method: str, namespace: str, source_ip: str,
                     user_agent: str) -> None:
    """A call to a namespace that is not exposed.

    This is the highest-value signal the RPC surface produces. The
    `admin`, `personal`, `debug` and `miner` namespaces control node
    administration and, historically, account unlocking -- exposing them on a
    public interface has led to direct theft. A request for one of these
    methods from an external address is either a misconfigured internal tool
    or someone checking whether this node is the one left open.
    """
    log.warning(
        "Blocked RPC call to restricted namespace: %s", method,
        extra={"ecs": {
            "event": {"kind": "alert", "category": ["web", "intrusion_detection"],
                      "type": ["denied"], "action": "rpc_unauthorized",
                      "outcome": "success", "severity": 90,
                      "dataset": "blockchain.rpc"},
            "blockchain": {"rpc": {"method": method, "namespace": namespace}},
            "rule": {"name": f"restricted_namespace.{namespace}"},
            "source": {"ip": source_ip},
            "user_agent": {"original": user_agent},
            "http": {"request": {"method": "POST"},
                     "response": {"status_code": 403}},
            "url": {"path": "/"},
        }},
    )


def rpc_expensive(method: str, source_ip: str, block_range: int,
                  duration_ms: float) -> None:
    """A query whose cost scales with a caller-controlled range.

    `eth_getLogs` over a very wide block range is the canonical example: the
    caller chooses how much work the node does, so an unbounded range is a
    denial-of-service primitive that costs the attacker one HTTP request.
    """
    log.warning(
        "Expensive RPC call: %s over %d blocks (%.0fms)",
        method, block_range, duration_ms,
        extra={"ecs": {
            "event": {"kind": "alert", "category": ["web"],
                      "action": "rpc_expensive", "outcome": "success",
                      "severity": 60, "dataset": "blockchain.rpc",
                      "duration": int(duration_ms * 1e6)},
            "blockchain": {"rpc": {"method": method, "block_range": block_range}},
            "source": {"ip": source_ip},
        }},
    )


def rpc_flood(source_ip: str, count: int, window_sec: int, user_agent: str) -> None:
    """Request-rate flooding against the RPC endpoint.

    Distinct from mempool flooding, and deliberately a separate event in a
    separate dataset. Both are "too much from one source", but the response
    differs: RPC flooding is handled at the edge with rate limiting, while
    mempool flooding needs transaction-level policy (minimum fees, per-sender
    limits). Collapsing them into one alert would tell an operator that
    something is being flooded without saying which lever to pull.
    """
    log.warning(
        "RPC request flood from %s: %d requests in %ds", source_ip, count, window_sec,
        extra={"ecs": {
            "event": {"kind": "alert", "category": ["web", "network"],
                      "type": ["denied"], "action": "rpc_flood",
                      "outcome": "success", "severity": 62,
                      "dataset": "blockchain.rpc"},
            "blockchain": {"rpc": {"request_count": count,
                                   "window_seconds": window_sec}},
            "source": {"ip": source_ip},
            "user_agent": {"original": user_agent},
        }},
    )


# --- P2P and mempool --------------------------------------------------------

def peer_connected(peer_id: str, source_ip: str, peer_count: int) -> None:
    log.info(
        "Peer connected: %s (%d total)", peer_id, peer_count,
        extra={"ecs": {
            "event": {"kind": "event", "category": ["network"],
                      "type": ["connection", "start"], "action": "peer_connected",
                      "outcome": "success", "dataset": "blockchain.p2p"},
            "blockchain": {"peer": {"id": peer_id, "count": peer_count}},
            "source": {"ip": source_ip},
        }},
    )


def peer_disconnected(peer_id: str, reason: str, peer_count: int) -> None:
    log.info(
        "Peer disconnected: %s (%s)", peer_id, reason,
        extra={"ecs": {
            "event": {"kind": "event", "category": ["network"],
                      "type": ["connection", "end"], "action": "peer_disconnected",
                      "outcome": "success", "reason": reason,
                      "dataset": "blockchain.p2p"},
            "blockchain": {"peer": {"id": peer_id, "count": peer_count}},
        }},
    )


def peer_churn(peer_count: int, window_events: int) -> None:
    """Rapid connect/disconnect cycling.

    Worth alerting on because it is what the early stage of an eclipse attack
    looks like: an attacker repeatedly fills the peer table with nodes it
    controls, trying to displace honest peers until the victim's entire view
    of the network comes from the attacker.
    """
    log.warning(
        "High peer churn: %d peer events, %d peers remain", window_events, peer_count,
        extra={"ecs": {
            "event": {"kind": "alert", "category": ["network"],
                      "action": "peer_churn", "outcome": "failure",
                      "severity": 70, "dataset": "blockchain.p2p"},
            "blockchain": {"peer": {"count": peer_count, "churn_events": window_events}},
        }},
    )


def tx_received(tx_hash: str, source_ip: str, pool_size: int,
                origin: str = "rpc") -> None:
    """A transaction entered the mempool.

    `origin` separates transactions submitted directly over RPC from ones
    relayed by a peer. Without it, source.ip on a relayed transaction is the
    peer that forwarded it rather than whoever originated it, so a flood
    detection keyed on source.ip would accuse an honest peer of spamming
    simply for doing its job.
    """
    log.debug(
        "Transaction %s entered mempool", tx_hash[:12],
        extra={"ecs": {
            "event": {"kind": "event", "category": ["network"],
                      "action": "tx_received", "outcome": "success",
                      "dataset": "blockchain.mempool"},
            "blockchain": {"tx": {"hash": tx_hash, "origin": origin},
                           "mempool": {"size": pool_size}},
            "source": {"ip": source_ip},
        }},
    )


def tx_rejected(reason: str, source_ip: str, detail: str = "",
                origin: str = "rpc") -> None:
    log.warning(
        "Transaction rejected: %s", reason,
        extra={"ecs": {
            "event": {"kind": "event", "category": ["network"],
                      "action": "tx_rejected", "outcome": "failure",
                      "reason": reason, "severity": 35,
                      "dataset": "blockchain.mempool"},
            "blockchain": {"rejection_reason": reason, "tx": {"origin": origin}},
            "source": {"ip": source_ip},
        }},
    )


def mempool_flood(source_ip: str, count: int, window_sec: int, pool_size: int) -> None:
    log.warning(
        "Mempool flooding from %s: %d transactions in %ds", source_ip, count, window_sec,
        extra={"ecs": {
            "event": {"kind": "alert", "category": ["network", "intrusion_detection"],
                      "type": ["denied"], "action": "mempool_flood",
                      "outcome": "success", "severity": 65,
                      "dataset": "blockchain.mempool"},
            "blockchain": {"mempool": {"size": pool_size, "flood_count": count}},
            "source": {"ip": source_ip},
        }},
    )


def node_started(node_id: str, validators: int, rpc_port: int,
                 genesis_time: float = 0.0) -> None:
    """Startup record.

    genesis_time is logged because it is the most common cause of a network
    that forms but never agrees: two nodes with different genesis times derive
    different slot numbers and reject each other's blocks as wrong_proposer
    indefinitely. Having it in the log turns a confusing networking symptom
    into a one-line diff.
    """
    log.info(
        "Node %s started with %d validators, RPC on :%d (genesis=%d)",
        node_id, validators, rpc_port, int(genesis_time),
        extra={"ecs": {
            "event": {"kind": "event", "category": ["process"], "type": ["start"],
                      "action": "node_start", "outcome": "success",
                      "dataset": "blockchain.consensus"},
            "blockchain": {"validator": {"count": validators},
                           "genesis_time": int(genesis_time)},
        }},
    )
