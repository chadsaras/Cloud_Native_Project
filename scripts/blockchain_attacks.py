#!/usr/bin/env python3
"""Reproducible attack scenarios against the blockchain node.

Each scenario drives exactly one detection rule so a demo can show a named
rule firing on demand rather than waiting for something interesting to happen.

Usage:
    python3 scripts/blockchain_attacks.py --scenario rpc_namespace_probe
    python3 scripts/blockchain_attacks.py --scenario all
    python3 scripts/blockchain_attacks.py --list
"""

import argparse
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request

# RFC 5737 documentation addresses - never routable, never a real host.
SCANNER_IP = "192.0.2.66"
EXHAUSTER_IP = "192.0.2.207"
FLOODER_IP = "192.0.2.131"
CHURN_IP = "192.0.2.44"

SCAN_TOOLS = ["python-requests/2.31.0", "curl/8.4.0", "Go-http-client/2.0",
              "Nikto/2.5.0", "zgrab/0.x"]


def rpc(target, method, params=None, ip=None, ua=None, timeout=10):
    body = json.dumps({"jsonrpc": "2.0", "id": 1,
                       "method": method, "params": params or []}).encode()
    req = urllib.request.Request(target, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Forwarded-For", ip or "203.0.113.10")
    req.add_header("User-Agent", ua or "sentinel-demo/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"http_error": exc.code}
    except Exception as exc:                      # noqa: BLE001
        return {"error": str(exc)}


def rpc_batch(target, calls, ip=None, ua=None):
    body = json.dumps([
        {"jsonrpc": "2.0", "id": i, "method": m, "params": p}
        for i, (m, p) in enumerate(calls)
    ]).encode()
    req = urllib.request.Request(target, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Forwarded-For", ip or "203.0.113.10")
    req.add_header("User-Agent", ua or "sentinel-demo/1.0")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as exc:                      # noqa: BLE001
        return {"error": str(exc)}


# --- Scenarios --------------------------------------------------------------

def scenario_rpc_namespace_probe(target, **kw):
    """Fires BC-001. Scans for exposed administrative RPC namespaces.

    This is the highest-value scenario in the set. A node bound to a public
    interface with the admin/personal/debug namespaces enabled is the
    configuration that has historically led to direct theft: an attacker finds
    an unlocked account via personal_listAccounts and drains it with
    eth_sendTransaction. Scanners sweep the internet for port 8545 doing
    exactly this sequence.
    """
    probes = [
        ("personal_listAccounts", []),
        ("personal_unlockAccount", ["0x0000000000000000000000000000000000000000", "", 0]),
        ("admin_nodeInfo", []),
        ("admin_peers", []),
        ("admin_addPeer", ["enode://attacker@192.0.2.66:30303"]),
        ("debug_traceTransaction", ["0x" + "00" * 32]),
        ("miner_start", [1]),
        ("txpool_status", []),
    ]
    print(f"[rpc_namespace_probe] {len(probes)} admin-namespace probes from {SCANNER_IP}")
    for method, params in probes:
        rpc(target, method, params, ip=SCANNER_IP, ua=random.choice(SCAN_TOOLS))
        time.sleep(0.2)

    # The same probes hidden inside one HTTP request. A detection that counts
    # HTTP requests sees one hit; a detection that counts RPC methods sees
    # eight. This is why BC-001 keys on blockchain.rpc.method.
    print(f"[rpc_namespace_probe] repeating as a single batched request (evasion)")
    rpc_batch(target, probes, ip=SCANNER_IP, ua="Go-http-client/2.0")


def scenario_getlogs_exhaustion(target, **kw):
    """Fires BC-002. Caller-controlled range turns one request into heavy work."""
    ranges = [(0, 1_000_000), (0, 500_000), (0, 250_000), (0, 999_999), (0, 100_000)]
    print(f"[getlogs_exhaustion] {len(ranges)} wide-range eth_getLogs from {EXHAUSTER_IP}")
    for start, end in ranges:
        rpc(target, "eth_getLogs",
            [{"fromBlock": hex(start), "toBlock": hex(end)}],
            ip=EXHAUSTER_IP, ua="python-requests/2.31.0")
        time.sleep(0.3)


def scenario_rpc_flood(target, **kw):
    """Fires BC-002. High request volume from one source.

    BC-002 covers both shapes of RPC abuse: expensive individual calls and
    high-volume cheap ones. They share a mitigation (rate limiting at the
    edge), which is why they share a rule.
    """
    print(f"[rpc_flood] 200 rapid requests from {FLOODER_IP}")
    for i in range(200):
        rpc(target, "eth_blockNumber", [], ip=FLOODER_IP, ua="Go-http-client/2.0")
        if i % 50 == 0 and i:
            print(f"  {i} sent")


def scenario_mempool_flood(target, **kw):
    """Fires BC-006. Transaction spam to fill the mempool."""
    print(f"[mempool_flood] 80 transactions from {FLOODER_IP}, then 40 replays")

    def spam(nonce):
        tx = json.dumps({
            "sender": f"0x{'ab' * 20}", "recipient": f"0x{'cd' * 20}",
            "value": 1, "nonce": nonce, "signature": "0x" + "11" * 64,
        })
        rpc(target, "eth_sendRawTransaction", [tx], ip=FLOODER_IP,
            ua="python-requests/2.31.0")

    for i in range(80):
        spam(i)
        time.sleep(0.05)

    # Replay the first 40. Real spam campaigns resubmit constantly, and the
    # duplicates are what produce tx_rejected events -- without them the only
    # signal is a single flood alert, which is too thin for BC-006 to key on.
    for i in range(40):
        spam(i)
        time.sleep(0.03)


def scenario_invalid_blocks(target, p2p_url=None, **kw):
    """Fires BC-007. Malformed and wrongly-signed blocks from a peer."""
    p2p = p2p_url or target.replace("8545", "30303")
    print(f"[invalid_blocks] 12 invalid blocks to {p2p}")

    bad_blocks = [
        # Well-formed shape, signature that cannot verify.
        {"height": 99, "slot": 9999, "parent_hash": "0x" + "00" * 32,
         "timestamp": time.time(), "proposer_index": 0,
         "proposer_pubkey": "0x04" + "11" * 64, "transactions": [],
         "signature": "0x" + "22" * 64},
        # Parent that does not exist.
        {"height": 5, "slot": 500, "parent_hash": "0x" + "de" * 32,
         "timestamp": time.time(), "proposer_index": 1,
         "proposer_pubkey": "0x04" + "33" * 64, "transactions": [],
         "signature": "0x" + "44" * 64},
        # Timestamp far in the future - would win fork choice if accepted.
        {"height": 6, "slot": 600, "parent_hash": "0x" + "00" * 32,
         "timestamp": time.time() + 86400, "proposer_index": 2,
         "proposer_pubkey": "0x04" + "55" * 64, "transactions": [],
         "signature": "0x" + "66" * 64},
        # Structurally malformed.
        {"height": "not-a-number", "slot": None},
    ]

    for _ in range(3):
        for block in bad_blocks:
            body = json.dumps({"from": "rogue-peer", "from_url": "http://192.0.2.66:30303",
                               "payload": block}).encode()
            req = urllib.request.Request(f"{p2p}/p2p/block", data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("X-Forwarded-For", SCANNER_IP)
            try:
                urllib.request.urlopen(req, timeout=5).read()
            except Exception:                     # noqa: BLE001
                pass
            time.sleep(0.15)


def scenario_peer_churn(target, p2p_url=None, **kw):
    """Fires BC-008. Rapid peer table cycling - the eclipse-attack signature."""
    p2p = p2p_url or target.replace("8545", "30303")
    print(f"[peer_churn] 20 rapid peer introductions to {p2p}")
    for i in range(20):
        body = json.dumps({"from": f"churn-peer-{i}",
                           "from_url": f"http://192.0.2.{40 + i % 20}:30303"}).encode()
        req = urllib.request.Request(f"{p2p}/p2p/hello", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Forwarded-For", CHURN_IP)
        try:
            urllib.request.urlopen(req, timeout=5).read()
        except Exception:                         # noqa: BLE001
            pass
        time.sleep(0.1)


def scenario_double_sign(target, **kw):
    """Fires BC-004 (critical). Stages the real-world slashing accident.

    Starts a SECOND node process configured with the same validator indices as
    the node already running. Both instances honestly do their duty, both sign
    a block for the same slot, and the pair of conflicting signatures is a
    slashable double proposal.

    This is not a contrived attack. It is the single most common way real
    validators get slashed: an operator fails over to a standby machine
    without cleanly stopping the original, and for a few slots the same keys
    are live in two places. The consequence is immediate ejection plus a
    correlation penalty that scales with how much stake was slashed alongside
    it -- which is why it is catastrophic for a large operator rather than
    merely expensive.
    """
    print("[double_sign] starting a rogue node with OVERLAPPING validator keys")
    print("              (simulates a failover that did not stop the original)")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    node_dir = os.path.join(root, "blockchain-node")

    # Read the target's actual chain parameters rather than trusting the
    # environment. Slot numbers are derived from genesis time, so a rogue node
    # that guesses wrong computes a completely different slot schedule -- in
    # testing it proposed at slot 1746 while the testnet was at slot 55, so no
    # slot ever collided and the scenario staged nothing while reporting
    # success. The node exposes these for exactly this reason.
    try:
        chain = json.load(urllib.request.urlopen(f"{target}/status", timeout=5))
        genesis = str(chain["genesis_time"])
        slot_seconds = str(chain["slot_seconds"])
        slots_per_epoch = str(chain["slots_per_epoch"])
        validator_count = str(chain["validator_count"])
        print(f"              inheriting chain params: genesis={genesis} "
              f"slot={slot_seconds}s validators={validator_count}")
    except Exception as exc:                      # noqa: BLE001
        print(f"              ERROR: could not read chain parameters: {exc}")
        return

    env = dict(os.environ)
    env.update({
        "NODE_ID": "node-rogue",
        # Deliberately far from the testnet's own range. run-local-testnet.sh
        # assigns 8545+i and 30303+i, so a rogue node on 8547/30305 collides
        # with the third node: it fails to bind, dies silently, and the
        # scenario reports success while staging nothing.
        "RPC_PORT": "8599",
        "P2P_PORT": "30399",
        "SELF_URL": "http://localhost:30399",
        # The overlap: this node runs validators 0 and 1, which the original
        # node is also running. Same VALIDATOR_SEED means identical keys.
        "VALIDATOR_INDICES": "0,1",
        "VALIDATOR_COUNT": validator_count,
        "BOOTNODES": kw.get("p2p_url") or "http://localhost:30303",
        "SLOT_SECONDS": slot_seconds,
        "SLOTS_PER_EPOCH": slots_per_epoch,
        "GENESIS_TIME": genesis,
    })

    log_path = kw.get("rogue_log", "/tmp/bcv/node-rogue.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w") as log_file:
        proc = subprocess.Popen(
            [sys.executable, "-m", "node.main"],
            cwd=node_dir, env=env, stdout=log_file, stderr=subprocess.STDOUT,
        )

    print(f"              rogue node pid={proc.pid}, log={log_path}")

    # Confirm it actually came up. A rogue node that failed to bind produces
    # no conflicting signatures at all, and the scenario would otherwise
    # report success having staged nothing.
    for _ in range(20):
        time.sleep(0.5)
        if proc.poll() is not None:
            print(f"              ERROR: rogue node exited early (code "
                  f"{proc.returncode}); see {log_path}")
            return
        probe = rpc("http://localhost:8599", "eth_blockNumber", timeout=2)
        if "result" in probe:
            print("              rogue node is up and signing")
            break
    else:
        print(f"              WARNING: rogue node did not become ready; "
              f"see {log_path}")

    # Long enough to overlap several slots the duplicated validators own.
    # Startup eats a few seconds of this, so the window is generous rather
    # than minimal - BC-004 fires on a single offence, but a scenario that
    # sometimes produces zero is not a demo.
    print("              running for 30s to overlap several slots...")
    time.sleep(30)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    print("              rogue node stopped")

    # Confirm the overlap produced what it was supposed to. A scenario that
    # silently stages nothing is worse than one that fails loudly.
    try:
        after = json.load(urllib.request.urlopen(f"{target}/status", timeout=5))
        offences = after.get("slashable_offences", [])
        if offences:
            kinds = {}
            for o in offences:
                kinds[o["kind"]] = kinds.get(o["kind"], 0) + 1
            summary = ", ".join(f"{v} {k}" for k, v in sorted(kinds.items()))
            print(f"              target recorded {len(offences)} offences: {summary}")
        else:
            print("              WARNING: target recorded NO slashable offences. "
                  "Check that the rogue node shared the chain's genesis time.")
    except Exception:                             # noqa: BLE001
        pass



def scenario_deep_reorg(target, **kw):
    """Fires BC-003. Builds a competing branch that rewrites recent history.

    Models a network partition healing: a group of validators kept producing
    while isolated, and when the partition ends their branch is longer and
    wins fork choice. The victim node rewinds and rebuilds.

    The branch is signed with real validator keys derived from the same seed
    the node uses, so every block passes signature and proposer checks. It has
    to be that way -- a branch of invalid blocks would be rejected as BC-007
    and would never trigger a reorg at all.
    """
    import importlib.util

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    node_pkg = os.path.join(root, "blockchain-node")
    if node_pkg not in sys.path:
        sys.path.insert(0, node_pkg)

    from node import crypto
    from node.chain import Block

    seed = os.getenv("VALIDATOR_SEED", "sentinel-testnet")

    # Validator count and timing come from the chain, not the environment.
    # Proposer assignment is `slot % validator_count`, so a count that differs
    # from the node's by even one makes every block claim the wrong proposer:
    # the first is rejected as wrong_proposer and the rest cascade into
    # unknown_parent, and the scenario stages nothing while appearing to run.
    # That is exactly what happened when this defaulted to 4 against a 6
    # validator testnet.
    status = json.load(urllib.request.urlopen(f"{target}/status", timeout=5))
    total = status["validator_count"]
    slot_seconds = status["slot_seconds"]

    keys, pubs = {}, {}
    for index in range(total):
        priv = int.from_bytes(
            crypto.sha3(f"{seed}:{index}".encode()), "big") % (crypto.N - 1) + 1
        keys[index] = priv
        pubs[index] = crypto.serialize_pubkey(crypto.private_to_public(priv))

    head_height = status["height"]
    current_slot = status["slot"]

    fork_depth = 4
    fork_height = max(1, head_height - fork_depth)

    resp = rpc(target, "eth_getBlockByNumber", [hex(fork_height)])
    fork_block = resp.get("result")
    if not fork_block:
        print(f"[deep_reorg] could not read block {fork_height}; skipping")
        return

    print(f"[deep_reorg] head is {head_height}; forking from {fork_height} "
          f"and building {fork_depth + 3} blocks")

    p2p = kw.get("p2p_url") or target.replace("8545", "30303")
    parent_hash = fork_block["hash"]
    slot = current_slot + 1
    results = []

    for offset in range(fork_depth + 3):
        height = fork_height + 1 + offset
        # Proposer assignment is round-robin over the active set, so the
        # branch must use whichever validator owns each slot or the node
        # rejects it as wrong_proposer.
        proposer = slot % total
        block = Block(
            height=height, slot=slot, parent_hash=parent_hash,
            timestamp=time.time(), proposer_index=proposer,
            proposer_pubkey=pubs[proposer], transactions=[],
        ).sign(keys[proposer])

        body = json.dumps({"from": "partitioned-peer",
                           "from_url": "http://192.0.2.88:30303",
                           "payload": block.to_dict()}).encode()

        # Generous timeout with one retry. Importing a block is synchronous
        # work on the node -- signature verification, fork choice, and on a
        # reorg a full balance rebuild -- and this scenario runs right after
        # double_sign has left the node processing a burst of events. A 5s
        # timeout here dropped a block mid-branch, which broke the parent
        # chain and turned the reorg into a stalled side branch.
        result = None
        for attempt in range(2):
            req = urllib.request.Request(f"{p2p}/p2p/block", data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("X-Forwarded-For", "192.0.2.88")
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    result = json.loads(r.read()).get("status")
                break
            except Exception as exc:              # noqa: BLE001
                result = f"error:{exc}"
                if attempt == 0:
                    time.sleep(2)

        # A dropped block breaks the chain for everything after it, so stop
        # rather than posting orphans that all fail as unknown_parent and
        # bury the real cause.
        if result is not None and str(result).startswith("error:"):
            print(f"  height {height:3} slot {slot:3} -> {result}")
            print("  aborting branch: the victim did not accept this block, so "
                  "every later block would be an orphan")
            results.append(result)
            break

        print(f"  height {height:3} slot {slot:3} proposer {proposer} -> {result}")
        results.append(result)
        parent_hash = block.hash()
        slot += 1
        time.sleep(0.2)

    outcomes = sorted(set(results))
    if "reorg" in results:
        print("  reorg accepted - the victim rewound and rebuilt")
    elif any(str(o).startswith("error:") for o in outcomes):
        print(f"  WARNING: no reorg - the victim did not respond in time "
              f"({outcomes}). It is probably still working through the previous "
              f"scenario; retry deep_reorg on its own.")
    elif "wrong_proposer" in outcomes:
        print(f"  WARNING: no reorg - blocks rejected as wrong_proposer. The "
              f"validator count or seed does not match the chain.")
    else:
        print(f"  WARNING: no reorg occurred (outcomes: {outcomes}). The branch "
              f"may not have grown past the victim's head.")


def scenario_validator_offline(target, **kw):
    """Fires BC-005. Stalls the node so it misses proposal duties.

    Uses SIGSTOP/SIGCONT rather than killing the process, because that
    reproduces the failure that actually happens: the node is still running
    and still holds its keys, but is not making progress -- a long GC pause, a
    stalled disk, an overloaded host. On resume it discovers the slots it
    slept through and reports each as a missed duty.
    """
    import signal
    import subprocess

    slot_seconds = int(os.getenv("SLOT_SECONDS", "2"))
    validator_count = int(os.getenv("VALIDATOR_COUNT", "6"))

    # The stall has to span more than one full pass through the validator set,
    # for two reasons.
    #
    # Coverage: proposer assignment is round-robin, so a node owning k of N
    # validators owns slots at k residues mod N. A stall of fewer than N slots
    # covers a contiguous run of residues that can miss all k of them, and the
    # scenario then reports success having produced no missed duties at all.
    # This is exactly what a 5-slot stall did against 6 validators.
    #
    # Volume: BC-005 needs 3 events to trigger, and a node owning k of N
    # validators misses roughly k duties per N slots. Two full passes yields
    # 2k, which clears the threshold for any k >= 2.
    # 2.5 passes rather than 2. At exactly two passes a node owning k of N
    # validators lands on k misses, which is BC-005's threshold exactly - and a
    # scenario that only just clears its threshold fails intermittently when
    # slot boundaries fall slightly differently. The extra half-pass buys
    # margin at the cost of a few seconds.
    stall_slots = max(15, (validator_count * 5) // 2)
    stall_for = slot_seconds * stall_slots

    # Resolve the PID from the RPC port, not by picking the first node.main
    # process. With a multi-node testnet, pgrep order is arbitrary, so stalling
    # pids[0] stalls some node - and the missed-duty events then land in a
    # different node's log than the one the evaluation reads, which looks
    # exactly like a broken rule.
    port = target.rsplit(":", 1)[-1].split("/")[0]
    pid = None
    try:
        out = subprocess.run(["lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN"],
                             capture_output=True, text=True, timeout=10)
        pids = [int(x) for x in out.stdout.split() if x.strip()]
        pid = pids[0] if pids else None
    except Exception:                             # noqa: BLE001
        pid = None

    if pid is None:
        try:
            out = subprocess.run(["pgrep", "-f", "node.main"],
                                 capture_output=True, text=True, timeout=10)
            pids = [int(x) for x in out.stdout.split() if x.strip()]
            pid = pids[0] if pids else None
            if pid:
                print("[validator_offline] WARNING: could not map the RPC port to a "
                      "process; falling back to the first node found, whose log may "
                      "not be the one you evaluate")
        except Exception as exc:                  # noqa: BLE001
            print(f"[validator_offline] could not find node process: {exc}")
            return

    if pid is None:
        print("[validator_offline] no running node found; skipping")
        return
    print(f"[validator_offline] SIGSTOP pid {pid} for {stall_for}s "
          f"(~{stall_slots} slots, {validator_count} validators)")
    try:
        os.kill(pid, signal.SIGSTOP)
        time.sleep(stall_for)
    finally:
        os.kill(pid, signal.SIGCONT)
    print(f"[validator_offline] resumed; node should now report missed duties")
    time.sleep(3)


SCENARIOS = {
    "rpc_namespace_probe": scenario_rpc_namespace_probe,
    "getlogs_exhaustion": scenario_getlogs_exhaustion,
    "rpc_flood": scenario_rpc_flood,
    "mempool_flood": scenario_mempool_flood,
    "invalid_blocks": scenario_invalid_blocks,
    "peer_churn": scenario_peer_churn,
    "double_sign": scenario_double_sign,
    "deep_reorg": scenario_deep_reorg,
    "validator_offline": scenario_validator_offline,
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default="http://localhost:8545",
                        help="node JSON-RPC endpoint")
    parser.add_argument("--p2p-url", default=None, help="node P2P endpoint")
    parser.add_argument("--scenario", choices=list(SCENARIOS) + ["all"])
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--rogue-log", default="/tmp/bcv/node-rogue.log")
    args = parser.parse_args()

    if args.list:
        print("\nScenarios:\n")
        for name, fn in SCENARIOS.items():
            first = (fn.__doc__ or "").strip().split("\n")[0]
            print(f"  {name:22} {first}")
        print()
        return 0

    if not args.scenario:
        parser.print_help()
        return 2

    probe = rpc(args.target, "eth_blockNumber")
    if "result" not in probe:
        print(f"error: node not reachable at {args.target} ({probe})", file=sys.stderr)
        return 1
    print(f"node is up at height {int(probe['result'], 16)}\n")

    kwargs = {"p2p_url": args.p2p_url, "rogue_log": args.rogue_log}
    if args.scenario == "all":
        for name, fn in SCENARIOS.items():
            fn(args.target, **kwargs)
            # Let the node drain before the next scenario. double_sign in
            # particular leaves a backlog of gossip and slashing evidence to
            # process, and the next scenario starting into that backlog is
            # what made deep_reorg time out intermittently.
            time.sleep(5)
            print()
    else:
        SCENARIOS[args.scenario](args.target, **kwargs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
