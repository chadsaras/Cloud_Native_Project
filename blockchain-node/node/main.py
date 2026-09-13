"""Node runtime: wires chain, consensus, RPC and P2P together.

Run one node for a single-validator chain, or several with a shared validator
set for a network that can fork, reorganise and disagree.
"""

import json
import os
import random
import threading
import time

from flask import Flask, jsonify, request

from . import crypto, events
from .chain import Block, Blockchain, InvalidBlock, Transaction, SLOT_SECONDS, SLOTS_PER_EPOCH
from .consensus import Attestation, ConsensusState, Validator, ValidatorSet
from .p2p import PeerManager
from .rpc import create_rpc_app

MEMPOOL_LIMIT = int(os.getenv("MEMPOOL_LIMIT", "500"))
FLOOD_WINDOW_SEC = 10
FLOOD_THRESHOLD = int(os.getenv("MEMPOOL_FLOOD_THRESHOLD", "50"))


class Node:
    def __init__(self):
        self.node_id = os.getenv("NODE_ID", "node-0")
        self.chain_id = int(os.getenv("CHAIN_ID", "31337"))
        self.rpc_port = int(os.getenv("RPC_PORT", "8545"))
        self.p2p_port = int(os.getenv("P2P_PORT", "30303"))
        self.self_url = os.getenv("SELF_URL", f"http://localhost:{self.p2p_port}")

        self.chain = Blockchain()
        self.mempool: list = []
        self.mempool_seen: set = set()
        self.tx_rate: dict = {}

        # --- validator identity -------------------------------------------
        # Keys are derived deterministically from a seed so that every node in
        # the network computes the SAME validator set and therefore agrees on
        # who is meant to propose in each slot. With random keys per node,
        # every node would consider every block to come from the wrong
        # proposer and the network would never agree on anything.
        seed = os.getenv("VALIDATOR_SEED", "sentinel-testnet")
        total = int(os.getenv("VALIDATOR_COUNT", "4"))
        self.validator_set = ValidatorSet()
        self.validator_keys: dict = {}

        for index in range(total):
            privkey = int.from_bytes(
                crypto.sha3(f"{seed}:{index}".encode()), "big") % (crypto.N - 1) + 1
            pubkey = crypto.private_to_public(privkey)
            self.validator_set.add(Validator(
                index=index,
                pubkey=crypto.serialize_pubkey(pubkey),
                address=crypto.public_to_address(pubkey),
            ))
            self.validator_keys[index] = privkey

        # Which validators THIS process runs. Overlapping this set across two
        # processes is exactly the operator mistake that causes real slashing,
        # and scripts/blockchain_attacks.py uses it to stage that scenario.
        raw = os.getenv("VALIDATOR_INDICES", "")
        self.my_validators = (
            [int(x) for x in raw.split(",") if x.strip() != ""]
            if raw else list(range(total))
        )

        # Genesis time must be IDENTICAL across every node. Slot numbers are
        # derived from it, so nodes with different genesis times compute
        # different proposers for the same wall-clock moment and reject each
        # other's blocks forever -- a failure that looks like a networking
        # problem and is not.
        #
        # When unset, fall back to the top of the current hour rather than to
        # time.time(). Independently started nodes then still agree, so a plain
        # `docker compose up` forms a working network without anything having
        # to compute and inject a shared timestamp. Nodes started either side
        # of an hour boundary will disagree; the Makefile pins GENESIS_TIME
        # explicitly to remove even that window.
        configured = float(os.getenv("GENESIS_TIME", "0"))
        genesis_time = configured or (time.time() // 3600) * 3600
        self.genesis_time = genesis_time
        self.consensus = ConsensusState(self.validator_set, genesis_time)

        self.p2p = PeerManager(self.node_id, self.self_url)
        self.last_proposed_slot = -1
        self.last_finalized_epoch = -1
        self.running = True

    # --- convenience ------------------------------------------------------

    @property
    def peers(self) -> dict:
        return self.p2p.peers

    def add_peer_by_enode(self, enode: str) -> None:
        if "@" in enode:
            peer_id, addr = enode.removeprefix("enode://").split("@", 1)
            self.p2p.add_peer(peer_id, f"http://{addr}")

    # --- transactions -----------------------------------------------------

    def submit_transaction(self, tx: Transaction, source_ip: str,
                           origin: str = "rpc"):
        now = time.time()
        window = self.tx_rate.setdefault(source_ip, [])
        window.append(now)
        self.tx_rate[source_ip] = [t for t in window if now - t <= FLOOD_WINDOW_SEC]

        if len(self.tx_rate[source_ip]) == FLOOD_THRESHOLD:
            events.mempool_flood(source_ip, FLOOD_THRESHOLD, FLOOD_WINDOW_SEC,
                                 len(self.mempool))

        tx_hash = tx.hash()
        if tx_hash in self.mempool_seen:
            events.tx_rejected("duplicate", source_ip, tx_hash[:18], origin)
            return False, "already known"

        if len(self.mempool) >= MEMPOOL_LIMIT:
            events.tx_rejected("mempool_full", source_ip, origin=origin)
            return False, "mempool full"

        if tx.value < 0:
            events.tx_rejected("negative_value", source_ip, origin=origin)
            return False, "negative value"

        self.mempool.append(tx)
        self.mempool_seen.add(tx_hash)
        if len(self.mempool_seen) > 10000:
            self.mempool_seen = set(t.hash() for t in self.mempool)

        events.tx_received(tx_hash, source_ip, len(self.mempool), origin)
        self.p2p.broadcast("/p2p/tx", tx.to_dict())
        return True, tx_hash

    # --- block production -------------------------------------------------

    def maybe_propose(self) -> None:
        slot = self.consensus.current_slot()
        if slot <= self.last_proposed_slot:
            return

        # Genesis occupies slot 0, and validate() requires each block's slot to
        # strictly exceed its parent's. Proposing at slot 0 therefore builds a
        # block the proposer's own validation rejects. Real chains avoid this
        # by defining genesis as the slot-0 block and starting production at
        # slot 1; do the same rather than loosening the slot check, which is
        # load-bearing for detecting proposers that reuse a slot.
        if slot == 0:
            return

        proposer = self.validator_set.proposer_for_slot(slot)
        if proposer is None:
            return

        # Catch missed duties for validators we run but did not propose for.
        if self.last_proposed_slot >= 0:
            for missed in range(self.last_proposed_slot + 1, slot):
                expected = self.validator_set.proposer_for_slot(missed)
                if expected and expected.index in self.my_validators:
                    record = self.consensus.record_missed_proposal(missed, expected.index)
                    events.duty_missed(missed, expected.index, record["epoch"])

        self.last_proposed_slot = slot

        if proposer.index not in self.my_validators:
            return

        started = time.perf_counter()
        head = self.chain.head_block()
        txs, self.mempool = self.mempool[:20], self.mempool[20:]

        block = Block(
            height=head.height + 1,
            slot=slot,
            parent_hash=self.chain.head,
            timestamp=time.time(),
            proposer_index=proposer.index,
            proposer_pubkey=proposer.pubkey,
            transactions=txs,
        ).sign(self.validator_keys[proposer.index])

        offence = self.consensus.slashing.record_proposal(block)
        if offence:
            events.slashable_offence(offence, proposer)

        try:
            result = self.chain.add_block(block, self.validator_set)
        except InvalidBlock as exc:
            events.block_rejected(exc.reason, exc.detail, self.node_id, "127.0.0.1",
                                  block.height)
            return

        events.block_proposed(block, (time.perf_counter() - started) * 1000)
        self.p2p.broadcast("/p2p/block", block.to_dict())
        self._attest(block)

    def _attest(self, block: Block) -> None:
        """Every validator this process runs votes for the block."""
        for index in self.my_validators:
            validator = self.validator_set.by_index(index)
            if not validator or validator.slashed:
                continue
            attestation = Attestation(
                slot=block.slot, block_hash=block.hash(),
                validator_index=index, validator_pubkey=validator.pubkey,
            ).sign(self.validator_keys[index])

            offence = self.consensus.record_attestation(attestation)
            if offence:
                events.slashable_offence(offence, validator)

            self.p2p.broadcast("/p2p/attestation", attestation.to_dict())

        support = self.consensus.participation_rate(block.slot)
        if self.consensus.is_justified(block.slot, block.hash()):
            self.consensus.justified_height = block.height
            epoch = self.consensus.epoch_for_slot(block.slot)
            if epoch > self.last_finalized_epoch:
                self.consensus.finalized_height = block.height
                self.last_finalized_epoch = epoch
                events.epoch_finalized(epoch, block.height, support)

    def check_finality(self) -> None:
        slot = self.consensus.current_slot()
        epoch = self.consensus.epoch_for_slot(slot)
        behind = epoch - self.last_finalized_epoch
        # Ethereum enters the inactivity leak after 4 epochs without finality.
        if self.last_finalized_epoch >= 0 and behind >= 4:
            events.finality_stalled(behind, self.consensus.justified_height,
                                    self.consensus.finalized_height)
            self.last_finalized_epoch = epoch   # alert once per stall, not per tick

    # --- inbound gossip ---------------------------------------------------

    def on_peer_block(self, payload: dict, peer_id: str, source_ip: str) -> str:
        try:
            block = Block.from_dict(payload)
        except (KeyError, ValueError, TypeError) as exc:
            events.block_rejected("malformed", str(exc), peer_id, source_ip)
            return "malformed"

        offence = self.consensus.slashing.record_proposal(block)
        if offence:
            events.slashable_offence(
                offence, self.validator_set.by_index(offence.validator_index))

        previous_head = self.chain.head_block()
        try:
            result = self.chain.add_block(block, self.validator_set)
        except InvalidBlock as exc:
            events.block_rejected(exc.reason, exc.detail, peer_id, source_ip,
                                  block.height)
            return exc.reason

        if result["status"] == "duplicate":
            return "duplicate"

        if result["status"] == "reorg":
            events.chain_reorg(result["reorg_depth"], previous_head,
                               block, result["common_ancestor"])

        events.block_imported(block, result["status"], result.get("reorg_depth", 0))

        # Relay to our other peers. Without this, gossip only ever travels one
        # hop: in a star topology where two nodes both peer with a bootnode
        # and not with each other, the bootnode receives every block and
        # forwards none, so the leaf nodes never converge.
        #
        # Loop prevention is the duplicate check above: a block we have
        # already stored returns early and is not re-broadcast, so a cycle in
        # the peer graph terminates after one pass rather than flooding
        # forever.
        self.p2p.broadcast("/p2p/block", block.to_dict())

        self._attest(block)
        return result["status"]

    def on_peer_attestation(self, payload: dict, peer_id: str) -> str:
        try:
            attestation = Attestation.from_dict(payload)
        except (KeyError, ValueError, TypeError):
            return "malformed"
        if not attestation.verify():
            events.block_rejected("bad_attestation_signature", "", peer_id, "0.0.0.0")
            return "bad_signature"

        # Drop attestations we already hold before doing anything else, so
        # relaying cannot loop.
        already = self.consensus.attestations.get(attestation.slot, {})
        if already.get(attestation.validator_index) is not None and \
                already[attestation.validator_index].block_hash == attestation.block_hash:
            return "duplicate"

        offence = self.consensus.record_attestation(attestation)
        if offence:
            events.slashable_offence(
                offence, self.validator_set.by_index(offence.validator_index))
        events.attestation_recorded(
            attestation, self.consensus.participation_rate(attestation.slot))

        self.p2p.broadcast("/p2p/attestation", attestation.to_dict())
        return "accepted"

    # --- loops ------------------------------------------------------------

    def consensus_loop(self) -> None:
        while self.running:
            try:
                self.maybe_propose()
                self.check_finality()
            except Exception:                    # noqa: BLE001
                logging_error()
            time.sleep(0.4)


def logging_error() -> None:
    import logging
    logging.getLogger("blockchain-node").exception(
        "Consensus loop iteration failed",
        extra={"ecs": {"event": {"kind": "event", "category": ["process"],
                                 "action": "consensus_error", "outcome": "failure",
                                 "dataset": "blockchain.consensus"}}},
    )


def create_p2p_app(node: Node) -> Flask:
    app = Flask(f"{node.node_id}-p2p")

    def source_ip() -> str:
        fwd = request.headers.get("X-Forwarded-For", "")
        return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "0.0.0.0")

    @app.route("/p2p/hello", methods=["POST"])
    def hello():
        body = request.get_json(silent=True) or {}
        peer_id, url = body.get("from"), body.get("from_url")
        if peer_id and url:
            node.p2p.add_peer(peer_id, url, source_ip())
        return jsonify({"id": node.node_id, "url": node.self_url,
                        "height": node.chain.height()})

    @app.route("/p2p/block", methods=["POST"])
    def block():
        body = request.get_json(silent=True) or {}
        status = node.on_peer_block(body.get("payload", {}),
                                    body.get("from", "unknown"), source_ip())
        return jsonify({"status": status})

    @app.route("/p2p/attestation", methods=["POST"])
    def attestation():
        body = request.get_json(silent=True) or {}
        return jsonify({"status": node.on_peer_attestation(
            body.get("payload", {}), body.get("from", "unknown"))})

    @app.route("/p2p/tx", methods=["POST"])
    def tx():
        body = request.get_json(silent=True) or {}
        try:
            transaction = Transaction.from_dict(body.get("payload", {}))
        except (KeyError, ValueError, TypeError):
            return jsonify({"status": "malformed"})
        accepted, detail = node.submit_transaction(transaction, source_ip(),
                                                   origin="p2p")
        return jsonify({"status": "accepted" if accepted else detail})

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok"}), 200

    return app


def main() -> None:
    events.configure_logging()
    node = Node()

    rpc_app = create_rpc_app(node)
    p2p_app = create_p2p_app(node)

    threading.Thread(
        target=lambda: p2p_app.run(host="0.0.0.0", port=node.p2p_port,
                                   threaded=True, use_reloader=False),
        daemon=True).start()

    threading.Thread(target=node.consensus_loop, daemon=True).start()

    # Dial the configured bootnodes.
    for entry in os.getenv("BOOTNODES", "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        threading.Thread(target=_dial, args=(node, entry), daemon=True).start()

    events.node_started(node.node_id, len(node.validator_set.validators),
                        node.rpc_port, node.genesis_time)
    rpc_app.run(host="0.0.0.0", port=node.rpc_port, threaded=True, use_reloader=False)


def _dial(node: Node, url: str) -> None:
    """Introduce ourselves to a bootnode, with retries while it starts up."""
    import urllib.request
    body = json.dumps({"from": node.node_id, "from_url": node.self_url}).encode()
    for _ in range(30):
        try:
            req = urllib.request.Request(
                f"{url}/p2p/hello", data=body, method="POST",
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                peer = json.loads(resp.read())
                node.p2p.add_peer(peer["id"], url)
                return
        except Exception:                        # noqa: BLE001
            time.sleep(2)


if __name__ == "__main__":
    main()
