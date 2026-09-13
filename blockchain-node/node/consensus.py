"""Proof-of-stake validator set, duty assignment, and slashing detection.

The slashing detector is the security-critical part of this node and the
reason the chain exists in this project at all. Ethereum's two slashable
offences are modelled directly:

  1. Double proposal  - one validator signs two different blocks for one slot
  2. Double vote      - one validator signs two different attestations for one
                        slot (the "surround vote" case is a generalisation of
                        this that needs vote source/target epochs; see the note
                        on SurroundVote below)

Both are detectable from signed messages alone, by anyone observing the
network. That property is what makes them monitorable: a node does not need
privileged access or the validator's key to prove the offence happened, it
just needs to have seen both signatures.

The overwhelmingly common real-world cause is not malice. It is an operator
running the same validator keys on two machines at once -- typically during a
failover that did not cleanly stop the original. Both instances do their duty
honestly, and the pair of signatures is slashable.
"""

import json
import time
from dataclasses import dataclass, field

from . import crypto
from .chain import SLOT_SECONDS, SLOTS_PER_EPOCH


@dataclass
class Validator:
    index: int
    pubkey: str
    address: str
    stake: int = 32
    slashed: bool = False
    active: bool = True

    def to_dict(self) -> dict:
        return {"index": self.index, "pubkey": self.pubkey,
                "address": self.address, "stake": self.stake,
                "slashed": self.slashed, "active": self.active}


@dataclass
class Attestation:
    """A validator's vote for the block it believes is canonical at a slot."""
    slot: int
    block_hash: str
    validator_index: int
    validator_pubkey: str
    signature: str = ""

    def signing_hash(self) -> bytes:
        payload = json.dumps(
            {"slot": self.slot, "block_hash": self.block_hash,
             "validator_index": self.validator_index},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return crypto.sha3(payload)

    def sign(self, privkey: int) -> "Attestation":
        self.signature = crypto.serialize_sig(crypto.sign(privkey, self.signing_hash()))
        return self

    def verify(self) -> bool:
        if not self.signature:
            return False
        try:
            return crypto.verify(
                crypto.deserialize_pubkey(self.validator_pubkey),
                self.signing_hash(),
                crypto.deserialize_sig(self.signature),
            )
        except (ValueError, IndexError):
            return False

    def to_dict(self) -> dict:
        return {"slot": self.slot, "block_hash": self.block_hash,
                "validator_index": self.validator_index,
                "validator_pubkey": self.validator_pubkey,
                "signature": self.signature}

    @staticmethod
    def from_dict(d: dict) -> "Attestation":
        return Attestation(
            slot=int(d["slot"]), block_hash=d["block_hash"],
            validator_index=int(d["validator_index"]),
            validator_pubkey=d.get("validator_pubkey", ""),
            signature=d.get("signature", ""),
        )


@dataclass
class SlashableOffence:
    kind: str                  # double_proposal | double_vote
    validator_index: int
    slot: int
    evidence: tuple            # the two conflicting hashes
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "validator_index": self.validator_index,
                "slot": self.slot, "evidence": list(self.evidence)}


class ValidatorSet:
    """The active validator registry plus deterministic duty assignment."""

    def __init__(self, validators=None):
        self.validators = list(validators or [])

    def add(self, validator: Validator) -> None:
        self.validators.append(validator)

    def by_index(self, index: int):
        for v in self.validators:
            if v.index == index:
                return v
        return None

    def active_validators(self) -> list:
        return [v for v in self.validators if v.active and not v.slashed]

    def proposer_for_slot(self, slot: int):
        """Deterministic round-robin over the active set.

        Real Ethereum shuffles the set with RANDAO so the next proposer cannot
        be predicted far ahead -- predictability invites targeted DoS against
        whoever is about to propose. Round-robin is used here because it makes
        "a block arrived from the wrong proposer" trivially checkable by any
        observer, which is exactly the property the BC-008 detection needs.
        """
        active = self.active_validators()
        if not active:
            return None
        return active[slot % len(active)]

    def attesters_for_slot(self, slot: int) -> list:
        """Every active validator attests every slot.

        Ethereum splits the set into per-slot committees so that the whole
        registry does not have to vote on everything. With a handful of
        validators there is nothing to split.
        """
        return self.active_validators()

    def total_stake(self) -> int:
        return sum(v.stake for v in self.active_validators())


class SlashingDetector:
    """Remembers what each validator signed, and catches conflicts.

    Memory is bounded by pruning slots older than RETAIN_SLOTS. A real client
    keeps this in a persistent anti-slashing database precisely so that a
    restart cannot forget a past signature and let the validator sign a
    conflicting message -- the interlock this node does not have, and a
    limitation worth stating rather than hiding.
    """

    RETAIN_SLOTS = 256

    def __init__(self):
        # (validator_index, slot) -> block hash it proposed / attested to
        self.proposals: dict = {}
        self.votes: dict = {}
        self.offences: list = []

        # (kind, validator_index, slot) already reported.
        #
        # Without this, one duplicated validator generates an offence on every
        # subsequent conflicting message rather than once per slot: a failover
        # lasting a minute produced 42 alerts for what is really a handful of
        # distinct offences. The underlying facts were correct, but an alert
        # stream like that is the thing that trains an operator to mute the
        # channel -- and this is the one alert that must never be muted.
        self._reported: set = set()

    def record_proposal(self, block) -> "SlashableOffence | None":
        key = (block.proposer_index, block.slot)
        block_hash = block.hash()
        previous = self.proposals.get(key)

        if previous is not None and previous != block_hash:
            signature = ("double_proposal", block.proposer_index, block.slot)
            if signature in self._reported:
                return None
            self._reported.add(signature)

            offence = SlashableOffence(
                kind="double_proposal",
                validator_index=block.proposer_index,
                slot=block.slot,
                evidence=(previous, block_hash),
            )
            self.offences.append(offence)
            return offence

        self.proposals[key] = block_hash
        self._prune(block.slot)
        return None

    def record_attestation(self, attestation) -> "SlashableOffence | None":
        key = (attestation.validator_index, attestation.slot)
        previous = self.votes.get(key)

        if previous is not None and previous != attestation.block_hash:
            signature = ("double_vote", attestation.validator_index, attestation.slot)
            if signature in self._reported:
                return None
            self._reported.add(signature)

            offence = SlashableOffence(
                kind="double_vote",
                validator_index=attestation.validator_index,
                slot=attestation.slot,
                evidence=(previous, attestation.block_hash),
            )
            self.offences.append(offence)
            return offence

        self.votes[key] = attestation.block_hash
        self._prune(attestation.slot)
        return None

    def _prune(self, current_slot: int) -> None:
        cutoff = current_slot - self.RETAIN_SLOTS
        if cutoff <= 0:
            return
        self.proposals = {k: v for k, v in self.proposals.items() if k[1] > cutoff}
        self.votes = {k: v for k, v in self.votes.items() if k[1] > cutoff}
        self._reported = {sig for sig in self._reported if sig[2] > cutoff}

        # NOTE: a real protocol also EJECTS a slashed validator from the active
        # set. This node deliberately does not, because ejection changes the
        # proposer schedule, and two nodes that eject at slightly different
        # moments would compute different proposers and split the chain. The
        # offence is recorded and alerted on; enforcement is out of scope.
        # See docs/roadmap.md.


class ConsensusState:
    """Tracks duties, attestations, justification and missed duties."""

    def __init__(self, validator_set: ValidatorSet, genesis_time: float):
        self.validator_set = validator_set
        self.genesis_time = genesis_time
        self.attestations: dict = {}      # slot -> {validator_index: Attestation}
        self.slashing = SlashingDetector()
        self.justified_height = 0
        self.finalized_height = 0
        self.missed_proposals: list = []

    def current_slot(self) -> int:
        return max(0, int((time.time() - self.genesis_time) // SLOT_SECONDS))

    def epoch_for_slot(self, slot: int) -> int:
        return slot // SLOTS_PER_EPOCH

    def record_attestation(self, attestation: Attestation):
        offence = self.slashing.record_attestation(attestation)
        self.attestations.setdefault(attestation.slot, {})[
            attestation.validator_index] = attestation
        return offence

    def attestation_support(self, slot: int, block_hash: str) -> int:
        """Stake weight backing a block at a slot."""
        votes = self.attestations.get(slot, {})
        total = 0
        for index, attestation in votes.items():
            if attestation.block_hash != block_hash:
                continue
            validator = self.validator_set.by_index(index)
            if validator and not validator.slashed:
                total += validator.stake
        return total

    def is_justified(self, slot: int, block_hash: str) -> bool:
        """Two thirds of stake is the supermajority threshold.

        The 2/3 figure is not arbitrary: it is what lets the protocol tolerate
        up to 1/3 of stake being adversarial while still guaranteeing that two
        conflicting blocks cannot both be justified -- any two 2/3 subsets must
        overlap in at least 1/3, and that overlap would be provably slashable.
        """
        total = self.validator_set.total_stake()
        if total == 0:
            return False
        return self.attestation_support(slot, block_hash) * 3 >= total * 2

    def record_missed_proposal(self, slot: int, validator_index: int) -> dict:
        record = {"slot": slot, "validator_index": validator_index,
                  "epoch": self.epoch_for_slot(slot)}
        self.missed_proposals.append(record)
        if len(self.missed_proposals) > 512:
            self.missed_proposals = self.missed_proposals[-512:]
        return record

    def participation_rate(self, slot: int) -> float:
        """Fraction of active validators that attested at a slot.

        A sustained drop is the clearest single indicator that something is
        wrong with the network rather than with any one node, which is why
        BC-005 alerts on it separately from a single validator missing duties.
        """
        active = self.validator_set.active_validators()
        if not active:
            return 0.0
        return len(self.attestations.get(slot, {})) / len(active)
