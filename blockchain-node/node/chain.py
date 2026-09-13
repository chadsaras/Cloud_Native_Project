"""Blocks, transactions and the canonical chain.

Deliberately a miniature: no state trie, no gas metering, no EVM. Account
balances are a flat dict. What it does model faithfully is the part this
project is actually about -- the events a node emits that an operator needs to
see: block production, fork choice, reorganisations, and invalid blocks
arriving from peers.
"""

import json
import time
from dataclasses import dataclass, field, asdict

from . import crypto

# Slot timing. Ethereum mainnet uses 12s slots and 32-slot epochs; this uses
# shorter values so a demo shows several epochs in a couple of minutes.
SLOT_SECONDS = int(__import__("os").getenv("SLOT_SECONDS", "3"))
SLOTS_PER_EPOCH = int(__import__("os").getenv("SLOTS_PER_EPOCH", "8"))

GENESIS_TIME = int(__import__("os").getenv("GENESIS_TIME", "0")) or None


@dataclass
class Transaction:
    sender: str
    recipient: str
    value: int
    nonce: int
    signature: str = ""

    def signing_hash(self) -> bytes:
        payload = json.dumps(
            {"from": self.sender, "to": self.recipient,
             "value": self.value, "nonce": self.nonce},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return crypto.sha3(payload)

    def hash(self) -> str:
        return "0x" + crypto.sha3(
            self.signing_hash() + bytes.fromhex(self.signature.removeprefix("0x") or "00")
        ).hex()

    def sign(self, privkey: int) -> "Transaction":
        self.signature = crypto.serialize_sig(crypto.sign(privkey, self.signing_hash()))
        return self

    def verify(self, pubkey: tuple) -> bool:
        if not self.signature:
            return False
        try:
            return crypto.verify(pubkey, self.signing_hash(),
                                 crypto.deserialize_sig(self.signature))
        except (ValueError, IndexError):
            return False

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Transaction":
        return Transaction(
            sender=d["sender"], recipient=d["recipient"], value=int(d["value"]),
            nonce=int(d["nonce"]), signature=d.get("signature", ""),
        )


@dataclass
class Block:
    height: int
    slot: int
    parent_hash: str
    timestamp: float
    proposer_index: int
    proposer_pubkey: str
    transactions: list = field(default_factory=list)
    signature: str = ""

    def signing_hash(self) -> bytes:
        """Hash over the block header, excluding the signature itself.

        Transactions are committed to by their hashes rather than their full
        bodies. That is a stand-in for a Merkle root: it keeps the header a
        fixed size and means a block's identity does not change if a peer
        re-serialises the transaction list differently.
        """
        payload = json.dumps(
            {
                "height": self.height,
                "slot": self.slot,
                "parent_hash": self.parent_hash,
                "timestamp": round(self.timestamp, 3),
                "proposer_index": self.proposer_index,
                "tx_hashes": [t.hash() for t in self.transactions],
            },
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return crypto.sha3(payload)

    def hash(self) -> str:
        return "0x" + crypto.sha3(self.signing_hash()).hex()

    def sign(self, privkey: int) -> "Block":
        self.signature = crypto.serialize_sig(crypto.sign(privkey, self.signing_hash()))
        return self

    def verify_signature(self) -> bool:
        if not self.signature or not self.proposer_pubkey:
            return False
        try:
            return crypto.verify(
                crypto.deserialize_pubkey(self.proposer_pubkey),
                self.signing_hash(),
                crypto.deserialize_sig(self.signature),
            )
        except (ValueError, IndexError):
            return False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["transactions"] = [t.to_dict() for t in self.transactions]
        d["hash"] = self.hash()
        return d

    @staticmethod
    def from_dict(d: dict) -> "Block":
        return Block(
            height=int(d["height"]), slot=int(d["slot"]),
            parent_hash=d["parent_hash"], timestamp=float(d["timestamp"]),
            proposer_index=int(d["proposer_index"]),
            proposer_pubkey=d.get("proposer_pubkey", ""),
            transactions=[Transaction.from_dict(t) for t in d.get("transactions", [])],
            signature=d.get("signature", ""),
        )


class InvalidBlock(Exception):
    """Raised with a machine-readable reason.

    The reason string becomes `blockchain.rejection_reason` in the logs, which
    is what makes BC-008 able to distinguish a peer sending malformed garbage
    from a peer sending well-formed blocks signed by the wrong validator. Those
    are very different situations: the first is usually a version mismatch,
    the second is an attack.
    """
    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


def genesis_block() -> Block:
    """A fixed genesis every node agrees on.

    Timestamp and signature are pinned to constants rather than generated, so
    that independently started nodes compute an identical genesis hash. If they
    did not, every node would consider every peer to be on a different chain.
    """
    return Block(
        height=0, slot=0,
        parent_hash="0x" + "00" * 32,
        timestamp=0.0,
        proposer_index=-1,
        proposer_pubkey="",
        transactions=[],
        signature="",
    )


class Blockchain:
    """Block store plus fork choice.

    Keeps every block it has seen, not just the canonical ones, because a
    reorganisation means promoting a previously non-canonical branch -- and
    because the discarded branch is evidence an operator wants to look at
    after the fact.
    """

    def __init__(self, on_event=None):
        self.blocks: dict = {}          # hash -> Block
        self.children: dict = {}        # parent hash -> [child hash]
        self.head: str = ""
        self.balances: dict = {}
        self.on_event = on_event or (lambda *a, **k: None)

        g = genesis_block()
        self.blocks[g.hash()] = g
        self.head = g.hash()
        self.genesis_hash = g.hash()

    # --- accessors ---------------------------------------------------------

    def head_block(self) -> Block:
        return self.blocks[self.head]

    def height(self) -> int:
        return self.head_block().height

    def get(self, block_hash: str):
        return self.blocks.get(block_hash)

    def canonical_chain(self) -> list:
        """Walk back from head to genesis, then reverse."""
        chain, cursor = [], self.head
        while cursor in self.blocks:
            block = self.blocks[cursor]
            chain.append(block)
            if block.height == 0:
                break
            cursor = block.parent_hash
        return list(reversed(chain))

    def block_at_height(self, height: int):
        cursor = self.head
        while cursor in self.blocks:
            block = self.blocks[cursor]
            if block.height == height:
                return block
            if block.height < height or block.height == 0:
                return None
            cursor = block.parent_hash
        return None

    def is_canonical(self, block_hash: str) -> bool:
        cursor = self.head
        target = self.blocks.get(block_hash)
        if not target:
            return False
        while cursor in self.blocks:
            if cursor == block_hash:
                return True
            block = self.blocks[cursor]
            if block.height <= target.height or block.height == 0:
                return False
            cursor = block.parent_hash
        return False

    # --- validation --------------------------------------------------------

    def validate(self, block: Block, validator_set=None) -> None:
        """Raise InvalidBlock if the block must not be accepted."""
        if block.height == 0:
            raise InvalidBlock("genesis_replay", "genesis cannot be imported")

        parent = self.blocks.get(block.parent_hash)
        if parent is None:
            raise InvalidBlock("unknown_parent", block.parent_hash[:18])

        if block.height != parent.height + 1:
            raise InvalidBlock(
                "bad_height", f"got {block.height}, parent is {parent.height}")

        if block.slot <= parent.slot:
            raise InvalidBlock(
                "slot_not_advancing", f"slot {block.slot} <= parent {parent.slot}")

        # A block dated far in the future would let a proposer claim slots that
        # have not happened yet and win fork choice against honest proposers.
        if block.timestamp > time.time() + (SLOT_SECONDS * 2):
            raise InvalidBlock("timestamp_in_future", f"{block.timestamp:.1f}")

        if not block.verify_signature():
            raise InvalidBlock("bad_signature", f"proposer {block.proposer_index}")

        if validator_set is not None:
            expected = validator_set.proposer_for_slot(block.slot)
            if expected is None or expected.index != block.proposer_index:
                raise InvalidBlock(
                    "wrong_proposer",
                    f"slot {block.slot} belongs to "
                    f"{expected.index if expected else 'nobody'}, "
                    f"block claims {block.proposer_index}",
                )
            validator = validator_set.by_index(block.proposer_index)
            if validator and validator.pubkey != block.proposer_pubkey:
                raise InvalidBlock(
                    "pubkey_mismatch", f"validator {block.proposer_index}")

        for tx in block.transactions:
            if tx.value < 0:
                raise InvalidBlock("negative_value", tx.hash()[:18])

    # --- insertion and fork choice ----------------------------------------

    def add_block(self, block: Block, validator_set=None) -> dict:
        """Validate and insert. Returns a description of what changed.

        The return value distinguishes an ordinary extension from a
        reorganisation, and reports the reorg depth -- which is the number the
        detection rule BC-004 thresholds on.
        """
        block_hash = block.hash()
        if block_hash in self.blocks:
            return {"status": "duplicate", "hash": block_hash}

        self.validate(block, validator_set)

        self.blocks[block_hash] = block
        self.children.setdefault(block.parent_hash, []).append(block_hash)

        previous_head = self.head
        previous_height = self.blocks[previous_head].height

        if block.parent_hash == previous_head:
            self.head = block_hash
            self._apply(block)
            return {"status": "extended", "hash": block_hash,
                    "height": block.height, "reorg_depth": 0}

        # A block that does not build on the head is a fork. Fork choice here
        # is longest-chain, with the earlier-arriving block winning ties.
        # Real consensus uses LMD-GHOST weighted by attestations; this is the
        # simplification that matters least for the monitoring story, because
        # what an operator sees either way is "the head moved sideways".
        if block.height > previous_height:
            common = self._common_ancestor(previous_head, block_hash)
            depth = previous_height - self.blocks[common].height
            self.head = block_hash
            self._rebuild_balances()
            return {"status": "reorg", "hash": block_hash, "height": block.height,
                    "reorg_depth": depth, "common_ancestor": common,
                    "orphaned_head": previous_head}

        return {"status": "side_branch", "hash": block_hash, "height": block.height,
                "reorg_depth": 0}

    def _common_ancestor(self, a: str, b: str) -> str:
        seen = set()
        cursor = a
        while cursor in self.blocks:
            seen.add(cursor)
            if self.blocks[cursor].height == 0:
                break
            cursor = self.blocks[cursor].parent_hash
        cursor = b
        while cursor in self.blocks:
            if cursor in seen:
                return cursor
            if self.blocks[cursor].height == 0:
                break
            cursor = self.blocks[cursor].parent_hash
        return self.genesis_hash

    def _apply(self, block: Block) -> None:
        for tx in block.transactions:
            self.balances[tx.sender] = self.balances.get(tx.sender, 0) - tx.value
            self.balances[tx.recipient] = self.balances.get(tx.recipient, 0) + tx.value

    def _rebuild_balances(self) -> None:
        """Recompute from genesis after a reorg.

        Wasteful, and correct. Undoing the orphaned branch and replaying the
        new one is what a real client does; at this chain's size replaying
        everything is simpler and cannot drift out of sync with the block
        store, which is the bug that version would risk.
        """
        self.balances = {}
        for block in self.canonical_chain():
            self._apply(block)
