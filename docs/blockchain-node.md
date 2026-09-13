# The blockchain node: what it models and what it does not

`blockchain-node/` is a miniature proof-of-stake chain that exists to be
monitored. It is the workload this platform watches, not a product in itself.

Its design is driven by one question: **what does a real node emit that an
operator needs to see?** Everything that serves that question is modelled
faithfully. Everything else is simplified, and the simplifications are listed
here rather than left for someone to discover.

The evidence behind the choices — real client log formats, the attack data, the
slashing rules — is in [`blockchain-use-cases.md`](blockchain-use-cases.md).

---

## Modelled faithfully

### Real ECDSA over secp256k1

`node/crypto.py` implements the actual curve Ethereum uses, from scratch, with
no third-party dependency. Signatures are real: signed with RFC 6979
deterministic nonces and verified against the curve.

This matters because **the slashing detector is only meaningful if a signature
genuinely binds a validator identity to a block**. If signing were a stand-in —
an HMAC, or a string comparison — then "this validator signed two conflicting
blocks" would be a simulation of a simulation, and the central security claim
of the project would be hollow.

It is verified against published secp256k1 test vectors in
`tests/test_crypto.py`, not merely against itself. Hand-written curve code is
exactly the kind of thing that is subtly wrong while appearing to work: a
broken implementation happily verifies its own signatures while producing
points that are not on the curve.

One rule in there is load-bearing rather than decorative. **Low-s
normalisation** (EIP-2): both `s` and `N-s` are valid signatures over the same
message under textbook ECDSA. If high-s signatures were accepted, an attacker
could flip a validator's signature into a second, different-looking signature
for the same block — and the slashing detector, which keys on "did this
validator sign two different things", would report a false double-signing
offence. The detection depends on the malleability rule.

### Slashing conditions

Both of Ethereum's slashable offences are implemented as the protocol defines
them:

- **Double proposal** — one validator signs two different blocks for one slot
- **Double vote** — one validator signs two different attestations for one slot

The important property is that both are **detectable from signed messages
alone**. Anyone observing the network can prove the offence; no privileged
access and no access to the validator's key is required. That is what makes
them monitorable at all, and it is why `scripts/blockchain_attacks.py` can
stage one and have two independent nodes both detect it with identical
evidence hashes.

The scenario that stages it is not a contrived attack. `--scenario double_sign`
starts a second node configured with **overlapping validator keys**, which is
the single most common way real validators get slashed: an operator fails over
to a standby without cleanly stopping the original, and for a few slots the
same keys are live in two places. Both instances behave honestly. The pair of
signatures is still slashable.

### The JSON-RPC attack surface

`node/rpc.py` reproduces the namespace structure of a real execution client:
`eth`, `net` and `web3` are read-mostly and exposed; `admin`, `personal`,
`debug`, `miner` and `txpool` are administrative and are not.

Calls to administrative namespaces are **logged as security events with the
caller's address**, whether or not the namespace is enabled. An unsolicited
`admin_*` request is a strong signal that someone is scanning for exactly the
misconfiguration where those namespaces are reachable.

`RPC_ENABLED_NAMESPACES` is deliberately configurable so the insecure
configuration can be demonstrated on purpose rather than only described.

**Batch requests are supported, and that is a security decision.** JSON-RPC
lets a caller put many method calls in one HTTP request. A scanner can
therefore hide dozens of `admin_*` probes inside a single request. This is why
`BC-001` keys on distinct `blockchain.rpc.method` rather than on request count:
in testing, one batched request produced eight method-level alerts where a
request-counting rule would have seen a single hit.

### Fork choice and reorganisations

The chain keeps every block it has seen, not just canonical ones, and reports
reorganisation **depth** when the head moves sideways. Depth is the entire
signal: one- and two-block reorgs are routine and happen whenever two proposers
produce near-simultaneously, while deep reorgs mean a partition healing or an
actor rewriting history. `BC-003` thresholds on depth for that reason — a rule
firing on any reorg would be muted within a day.

---

## Simplified, deliberately

| Area | Real clients | This node | Why it is acceptable |
|---|---|---|---|
| Hashing | Keccak-256 | SHA3-256 | Python ships SHA3, not Keccak. Addresses are therefore **not** Ethereum-compatible. The chain is a monitored workload, not a wallet. |
| P2P transport | devp2p/RLPx over TCP, encrypted handshake, Kademlia discovery | HTTP POST to a static peer list | The monitored events — peers joining and leaving, churn, blocks attributed to a peer — have the same shape regardless of transport. |
| Fork choice | LMD-GHOST weighted by attestations | Longest chain, earliest arrival wins ties | What an operator sees either way is "the head moved sideways", with a depth. |
| Proposer selection | Shuffled by RANDAO | Round-robin | Round-robin makes "this block came from the wrong proposer" trivially checkable by any observer, which `BC-007` needs. Real shuffling exists to stop an attacker predicting and DoSing the next proposer. |
| State | Merkle-Patricia trie, EVM, gas | Flat balance dict, no execution | No detection in this project reads contract state. |
| Committees | Validator set split per slot | Every validator attests every slot | With a handful of validators there is nothing to split. |
| Anti-slashing | Persistent database that survives restart | In-memory, pruned after 256 slots | **This is the most significant gap.** See below. |
| Slashing enforcement | Offender ejected from the validator set | Recorded and alerted, not enforced | Ejection changes the proposer schedule; two nodes ejecting at slightly different moments would compute different proposers and split the chain. |

### The anti-slashing gap

A real validator client keeps its signing history in a **persistent database**
precisely so that a restart cannot forget a past signature and let the
validator sign a conflicting message. This node keeps that history in memory.

The consequence is real: restart this node and it will happily sign again for a
slot it already signed. That is the exact interlock the node lacks, and it is
worth being explicit about because the project's headline detection is about
double-signing. The node **detects** double-signing; it does not **prevent**
it. Those are different jobs, and a validator client must do both.

---

## Configuration that matters

**`GENESIS_TIME` must be identical across every node.** Slot numbers are
derived from it, so nodes with different genesis times compute different
proposers for the same wall-clock moment and reject each other's blocks
forever. This failure presents as a networking problem and is not one, which is
why `node_start` logs the genesis time — it turns a confusing symptom into a
one-line diff.

When unset, the node falls back to the top of the current hour rather than to
its own start time, so independently started nodes still agree and a plain
`docker compose up` forms a working network. `scripts/run-local-testnet.sh` and
the Kubernetes ConfigMap both pin it explicitly.

**`VALIDATOR_INDICES` must not overlap between nodes.** Overlapping slices
double-sign immediately. The Compose stack gives each of three nodes a distinct
pair out of six. `--scenario double_sign` stages the overlap on purpose.

**`VALIDATOR_SEED` must match across nodes.** Keys are derived deterministically
from it so that every node computes the same validator set and agrees on who
proposes when. With random per-node keys, every node would consider every block
to come from the wrong proposer.

---

## Running it

No Docker needed:

```bash
make chain-up                              # 3 nodes, 6 validators
make chain-status                          # head, peers, slashing evidence
make chain-attack SCENARIO=double_sign     # stage the slashing accident
make chain-verify                          # evaluate all rules on the capture
```

`make chain-scenarios` lists all nine. `--scenario all` runs every one, and
`tests/simulate_detections.py` then evaluates the rules against the captured
JSONL offline — the whole detection path is exercisable with nothing but Python.
