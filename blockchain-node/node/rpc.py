"""JSON-RPC 2.0 HTTP API.

Models the Ethereum node RPC surface closely enough to be attacked the same
way, because that attack surface is the point of this project.

NAMESPACE POLICY -- the security-critical design decision here:

An Ethereum execution client groups RPC methods into namespaces, and which of
them are reachable over HTTP is a startup flag. `eth` and `net` are read-mostly
and safe to expose. `admin`, `personal`, `debug` and `miner` are node
administration: they can add peers, dump state, and historically could unlock
accounts and send transactions from them.

The failure mode this node reproduces is a node bound to 0.0.0.0 with the
administrative namespaces enabled. Rather than merely rejecting those calls,
the node logs each one as a security event with the caller's address, because
an unsolicited `admin_*` request is a strong signal that someone is scanning
for exactly that misconfiguration.

ENABLED_NAMESPACES is intentionally settable so the insecure configuration can
be demonstrated deliberately. Default is the safe set.
"""

import json
import os
import time
from collections import defaultdict, deque

from flask import Flask, g, jsonify, request

from . import events
from .chain import Transaction

# Namespaces reachable over HTTP. Matches Geth's --http.api flag in spirit.
ENABLED_NAMESPACES = set(
    os.getenv("RPC_ENABLED_NAMESPACES", "eth,net,web3").split(",")
)

# Namespaces that are administrative. A call to one of these is logged as a
# security event whether or not it is enabled.
RESTRICTED_NAMESPACES = {"admin", "personal", "debug", "miner", "txpool"}

# eth_getLogs over a caller-chosen range is the classic resource-exhaustion
# vector: the caller decides how much work the node does.
MAX_BLOCK_RANGE = int(os.getenv("RPC_MAX_BLOCK_RANGE", "1000"))

# Per-IP request accounting, for flood detection.
RATE_WINDOW_SEC = 10
RATE_THRESHOLD = int(os.getenv("RPC_RATE_THRESHOLD", "120"))


def create_rpc_app(node) -> Flask:
    app = Flask(__name__)
    request_log = defaultdict(deque)   # source ip -> deque[timestamp]

    def client_ip() -> str:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote_addr or "0.0.0.0"

    def namespace_of(method: str) -> str:
        return method.split("_", 1)[0] if "_" in method else "unknown"

    def rpc_error(request_id, code: int, message: str, status: int = 200):
        return jsonify({"jsonrpc": "2.0", "id": request_id,
                        "error": {"code": code, "message": message}}), status

    def rpc_result(request_id, result):
        return jsonify({"jsonrpc": "2.0", "id": request_id, "result": result})

    # --- method implementations -------------------------------------------

    def eth_blockNumber(params, ip):
        return hex(node.chain.height())

    def eth_chainId(params, ip):
        return hex(node.chain_id)

    def eth_getBalance(params, ip):
        address = params[0] if params else ""
        return hex(node.chain.balances.get(address, 0))

    def eth_getBlockByNumber(params, ip):
        raw = params[0] if params else "latest"
        if raw == "latest":
            block = node.chain.head_block()
        else:
            height = int(raw, 16) if isinstance(raw, str) and raw.startswith("0x") else int(raw)
            block = node.chain.block_at_height(height)
        return block.to_dict() if block else None

    def eth_getBlockByHash(params, ip):
        block = node.chain.get(params[0] if params else "")
        return block.to_dict() if block else None

    def eth_getLogs(params, ip):
        """Range-scanned query. Deliberately enforces a range cap."""
        filt = params[0] if params else {}
        from_block = filt.get("fromBlock", "0x0")
        to_block = filt.get("toBlock", "latest")

        start = 0 if from_block in ("earliest", None) else (
            int(from_block, 16) if isinstance(from_block, str) and from_block.startswith("0x")
            else int(from_block))
        end = node.chain.height() if to_block in ("latest", None) else (
            int(to_block, 16) if isinstance(to_block, str) and to_block.startswith("0x")
            else int(to_block))

        span = max(0, end - start)
        if span > MAX_BLOCK_RANGE:
            events.rpc_expensive("eth_getLogs", ip, span, 0.0)
            raise ValueError(
                f"requested range {span} exceeds limit {MAX_BLOCK_RANGE}")

        started = time.perf_counter()
        results = []
        for height in range(start, min(end, node.chain.height()) + 1):
            block = node.chain.block_at_height(height)
            if not block:
                continue
            for tx in block.transactions:
                results.append({"blockNumber": hex(height), "blockHash": block.hash(),
                                "transactionHash": tx.hash(),
                                "address": tx.recipient, "data": hex(tx.value)})
        elapsed = (time.perf_counter() - started) * 1000
        if span > MAX_BLOCK_RANGE // 4:
            events.rpc_expensive("eth_getLogs", ip, span, elapsed)
        return results

    def eth_sendRawTransaction(params, ip):
        try:
            payload = json.loads(params[0]) if params else {}
            tx = Transaction.from_dict(payload)
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            events.tx_rejected("malformed", ip, str(exc))
            raise ValueError("malformed transaction")
        accepted, reason = node.submit_transaction(tx, ip)
        if not accepted:
            raise ValueError(reason)
        return tx.hash()

    def eth_getTransactionCount(params, ip):
        address = params[0] if params else ""
        count = sum(
            1 for block in node.chain.canonical_chain()
            for tx in block.transactions if tx.sender == address
        )
        return hex(count)

    def net_peerCount(params, ip):
        return hex(len(node.peers))

    def net_version(params, ip):
        return str(node.chain_id)

    def web3_clientVersion(params, ip):
        return f"sentinel-node/v{os.getenv('SERVICE_VERSION', '0.3.0')}/python"

    # --- administrative methods -------------------------------------------
    # Present so that calling them produces a realistic response surface. They
    # are gated by ENABLED_NAMESPACES and every call is logged regardless.

    def admin_nodeInfo(params, ip):
        return {"id": node.node_id, "name": web3_clientVersion([], ip),
                "enode": f"enode://{node.node_id}@0.0.0.0:{node.p2p_port}",
                "protocols": {"eth": {"network": node.chain_id,
                                      "head": node.chain.head}}}

    def admin_peers(params, ip):
        return [{"id": pid, "enode": f"enode://{pid}@{addr}"}
                for pid, addr in node.peers.items()]

    def admin_addPeer(params, ip):
        node.add_peer_by_enode(params[0] if params else "")
        return True

    def personal_listAccounts(params, ip):
        return [v.address for v in node.validator_set.validators]

    def personal_unlockAccount(params, ip):
        # Never actually unlocks anything. The method exists so that a scanner
        # probing for it gets a plausible response shape while the attempt is
        # recorded -- a 'method not found' would tell the scanner to move on.
        return False

    def debug_traceTransaction(params, ip):
        return {"gas": 0, "failed": False, "returnValue": "", "structLogs": []}

    def miner_start(params, ip):
        return None

    def txpool_status(params, ip):
        return {"pending": hex(len(node.mempool)), "queued": "0x0"}

    METHODS = {
        "eth_blockNumber": eth_blockNumber,
        "eth_chainId": eth_chainId,
        "eth_getBalance": eth_getBalance,
        "eth_getBlockByNumber": eth_getBlockByNumber,
        "eth_getBlockByHash": eth_getBlockByHash,
        "eth_getLogs": eth_getLogs,
        "eth_sendRawTransaction": eth_sendRawTransaction,
        "eth_getTransactionCount": eth_getTransactionCount,
        "net_peerCount": net_peerCount,
        "net_version": net_version,
        "web3_clientVersion": web3_clientVersion,
        "admin_nodeInfo": admin_nodeInfo,
        "admin_peers": admin_peers,
        "admin_addPeer": admin_addPeer,
        "personal_listAccounts": personal_listAccounts,
        "personal_unlockAccount": personal_unlockAccount,
        "debug_traceTransaction": debug_traceTransaction,
        "miner_start": miner_start,
        "txpool_status": txpool_status,
    }

    # --- dispatch ----------------------------------------------------------

    @app.route("/", methods=["POST"])
    def handle_rpc():
        started = time.perf_counter()
        ip = client_ip()
        user_agent = request.headers.get("User-Agent", "-")

        # Flood accounting. Counted before dispatch so that a caller cannot
        # avoid it by sending methods that fail early.
        now = time.time()
        window = request_log[ip]
        window.append(now)
        while window and now - window[0] > RATE_WINDOW_SEC:
            window.popleft()
        if len(window) == RATE_THRESHOLD:
            events.rpc_flood(ip, len(window), RATE_WINDOW_SEC, user_agent)

        body = request.get_json(silent=True)
        if body is None:
            return rpc_error(None, -32700, "Parse error", 400)

        # Batch requests: a list of calls in one HTTP request. Worth supporting
        # because it is also an evasion technique -- a scanner can hide a
        # hundred admin_* probes inside a single HTTP request, and a detection
        # that counts HTTP requests rather than RPC methods would miss it.
        calls = body if isinstance(body, list) else [body]
        responses = []

        for call in calls:
            if not isinstance(call, dict):
                responses.append({"jsonrpc": "2.0", "id": None,
                                  "error": {"code": -32600, "message": "Invalid Request"}})
                continue

            request_id = call.get("id")
            method = str(call.get("method", ""))
            params = call.get("params", []) or []
            namespace = namespace_of(method)
            param_size = len(json.dumps(params))

            if namespace in RESTRICTED_NAMESPACES and namespace not in ENABLED_NAMESPACES:
                events.rpc_unauthorized(method, namespace, ip, user_agent)
                responses.append({"jsonrpc": "2.0", "id": request_id,
                                  "error": {"code": -32601,
                                            "message": f"the method {method} does not exist/is not available"}})
                continue

            handler = METHODS.get(method)
            if handler is None:
                # Unknown method. Logged as an ordinary request so that
                # enumeration of the method namespace is still countable.
                events.rpc_request(method, ip, 0.0, 404, namespace, param_size)
                responses.append({"jsonrpc": "2.0", "id": request_id,
                                  "error": {"code": -32601,
                                            "message": f"the method {method} does not exist/is not available"}})
                continue

            if namespace not in ENABLED_NAMESPACES and namespace not in ("eth", "net", "web3"):
                events.rpc_unauthorized(method, namespace, ip, user_agent)
                responses.append({"jsonrpc": "2.0", "id": request_id,
                                  "error": {"code": -32601, "message": "namespace not enabled"}})
                continue

            try:
                result = handler(params, ip)
                elapsed = (time.perf_counter() - started) * 1000
                events.rpc_request(method, ip, elapsed, 200, namespace, param_size)
                responses.append({"jsonrpc": "2.0", "id": request_id, "result": result})
            except ValueError as exc:
                elapsed = (time.perf_counter() - started) * 1000
                events.rpc_request(method, ip, elapsed, 400, namespace, param_size)
                responses.append({"jsonrpc": "2.0", "id": request_id,
                                  "error": {"code": -32602, "message": str(exc)}})
            except Exception as exc:           # noqa: BLE001 - RPC must not 500
                elapsed = (time.perf_counter() - started) * 1000
                events.rpc_request(method, ip, elapsed, 500, namespace, param_size)
                responses.append({"jsonrpc": "2.0", "id": request_id,
                                  "error": {"code": -32603, "message": "Internal error"}})

        if isinstance(body, list):
            return jsonify(responses)
        return jsonify(responses[0])

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok", "height": node.chain.height()}), 200

    @app.route("/status")
    def status():
        """Operational view, for the demo UI and for debugging."""
        from .chain import SLOT_SECONDS, SLOTS_PER_EPOCH
        return jsonify({
            "node_id": node.node_id,
            "chain_id": node.chain_id,
            # Chain timing is exposed so that tooling can derive the same slot
            # numbers this node does. Without it, anything that has to reason
            # about slots must be told the parameters out of band and silently
            # computes a different schedule when they disagree.
            "genesis_time": int(node.genesis_time),
            "slot_seconds": SLOT_SECONDS,
            "slots_per_epoch": SLOTS_PER_EPOCH,
            "validator_count": len(node.validator_set.validators),
            "height": node.chain.height(),
            "head": node.chain.head,
            "slot": node.consensus.current_slot(),
            "epoch": node.consensus.epoch_for_slot(node.consensus.current_slot()),
            "peers": list(node.peers),
            "mempool": len(node.mempool),
            "validators": [v.to_dict() for v in node.validator_set.validators],
            "finalized_height": node.consensus.finalized_height,
            "slashable_offences": [o.to_dict() for o in node.consensus.slashing.offences],
            "enabled_namespaces": sorted(ENABLED_NAMESPACES),
        }), 200

    return app
