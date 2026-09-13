# Blockchain use cases for this platform

Where the competencies this platform already has — heterogeneous log ingestion,
schema normalization, ingest-time enrichment, threshold and cardinality
detection over HTTP and authentication events, retention tiering — meet a real,
documented problem in the Ethereum operations world.

Every load-bearing claim below carries a primary source. Claims are tagged:

- **[V]** verified against a primary source (client source code, official docs,
  the consensus or execution specs, a first-party post-mortem)
- **[I]** reasonable inference from verified facts, stated as inference
- **[S]** speculation or a claim I could only reach through secondary reporting

---

## 1. Summary

Three use cases survive scrutiny. Two are strong.

**1. JSON-RPC endpoint security.** Ethereum execution clients expose an HTTP
JSON-RPC API. The Ethereum execution API specification defines **no
authentication mechanism at all** for the public namespaces — authentication
exists only for the `engine` namespace on a separate port **[V]**. Attackers
run continuous internet-wide scans against it; a six-month academic honeypot
captured **308.66 million RPC requests from 1,072 distinct IP addresses** and
attributed roughly **$18.56M** in theft to the groups it observed **[V]**. The
attack is a fixed method sequence — reconnaissance, then enumeration, then
execution — executed at up to **50 requests per second per source** **[V]**.
That is a per-source-IP threshold detection over HTTP requests, which is
structurally the same problem SEC-001 and SEC-003 already solve.

Critically, **Geth's own RPC log is not usable for this**: successful calls are
logged at `Debug` (below the default verbosity of 3) and the log context carries
`reqid`, `duration` and `err` but **no client IP** **[V]**. Detection therefore
has to come from a reverse-proxy access log in front of the RPC port — which is
exactly the nginx combined-log grok path `20-parse.conf` already implements.

**2. Log schema fragmentation across clients.** There is no common logging
schema across Ethereum clients. Four of nine major clients have no native JSON
log output at all; of those that do, the JSON key names differ per client
(Geth emits `t`/`lvl`/`msg`, not `@timestamp`/`log.level`/`message`) **[V]**.
Worse, the *same semantic event* is logged under different field names by every
client: a chain reorganisation is `drop`/`add` in Geth, `reorg_distance` in
Lighthouse, and `depth`/`distance` in Prysm **[V]**. ECS contains **no
blockchain fieldset and no blockchain-related issue or PR in its repository**
**[V]**. This is precisely the problem ECS solves for IT logs, unsolved for this
domain, and `30-normalize.conf` is the shape of the answer.

**3. Remote signer access monitoring (Web3Signer).** Smaller in scope but an
unusually clean fit: Web3Signer natively emits **ECS-formatted JSON**
(`--logging-format=ECS`) and has an access log that is **disabled by default**
(`--access-logs-enabled`, default `false`) **[V]**. Zero parser work; the
enrichment, redaction and detection tiers apply unchanged.

Section 2 answers the design question for our own node: what it
should log and under what field names. Ranked table in section 9, build plan
in section 10.

---

## 2. Designing the node's own logs

The monitored workload for this project is a minimal proof-of-stake node we
write ourselves, not a real client. That is the right call — it removes the
operational cost of running Geth plus a consensus client, and it lets the node
emit ECS JSON directly, which `docs/architecture.md` already argues for
("parsing a line you already control is wasted work").

It also creates an obligation: the node has to be a *faithful* miniature. If it
logs things no real client logs, or omits the things operators actually watch,
the detections built on top of it prove nothing. This section answers what to
log and under what field names, grounded in what real clients emit.

### 2.1 What real clients log, with real lines

All field names below are read from client source, not reconstructed from
documentation. Message strings are quoted exactly.

**Per-slot status (the heartbeat).** Lighthouse's notifier emits one line per
slot at `info!`:

```rust
info!(
    peers = peer_count_pretty(connected_peer_count),
    exec_hash = block_hash,
    finalized_root = %finalized_checkpoint.root.short(),
    finalized_epoch = %finalized_checkpoint.epoch,
    epoch = %current_epoch,
    block = block_info,
    slot = %current_slot,
    "Synced"
);
```

and when not synced, the same field set under `"Searching for peers"` with
`head_slot` and `current_slot`. Source:
[`beacon_node/client/src/notifier.rs`](https://github.com/sigp/lighthouse/blob/stable/beacon_node/client/src/notifier.rs) **[V]**

This single line is the most important design template in the document. It is
a periodic, self-describing status record carrying sync state, peer count, head
slot, current slot and finalized checkpoint — i.e. everything needed to answer
"is this node healthy" without correlating anything. It is also, structurally,
exactly what `10-input.conf`'s heartbeat does for the pipeline: a known-good
signal whose *absence* is the alert.

**Peer health.** Same file, escalated to `warn!`:

```rust
warn!(peer_count = peer_count_pretty(connected_peer_count), "Low peer count");
```

**Block proposal.** Nimbus logs `"Block proposed"`; Prysm's propose path logs
`"Failed to propose block"` and `"Failed to log proposed block"`; Lighthouse's
validator monitor logs a *missed* proposal at `error!`:

```rust
error!(index = i, %slot, …, "Validator missed a block");
```

Sources:
[nimbus `beacon_validators.nim`](https://github.com/status-im/nimbus-eth2/blob/stable/beacon_chain/validators/beacon_validators.nim),
[prysm `validator/client/propose.go`](https://github.com/OffchainLabs/prysm/blob/develop/validator/client/propose.go),
[lighthouse `validator_monitor.rs`](https://github.com/sigp/lighthouse/blob/stable/beacon_node/beacon_chain/src/validator_monitor.rs) **[V]**

**Attestation.** Prysm attaches this field set to attestation logs:

```go
logrus.Fields{
  "pubkey":         …, "slot":        …, "committeeIndex": …,
  "blockRoot":      …, "sourceEpoch": …, "sourceRoot":     …,
  "targetEpoch":    …, "targetRoot":  …, "signature":      …,
}
```

Source:
[prysm `validator/client/attest.go`](https://github.com/OffchainLabs/prysm/blob/develop/validator/client/attest.go) **[V]**

Lighthouse's validator monitor reports attestation outcomes per epoch with
`epoch` and `validator`: `"Previous epoch attestation success"` (`info!`),
`"Previous epoch attestation missing"` (`warn!`), `"Attestation failed to match
head"`, `"Attestation failed to match target"`, `"Potential sub-optimal
inclusion delay"`, plus aggregate variants `"Previous epoch attestation(s)
missing"` carrying a list of validator ids **[V]**.

**Justification and finalization.** Lighthouse carries `finalized_root` and
`finalized_epoch` on the per-slot status line rather than logging a separate
"finalized" event, and logs `"Error updating finalization"` on failure **[V]**.
Nimbus logs `"Block DAG initialized"` and `"Checkpoint written to database"`
**[V]**. The practical lesson: **finality is reported as state on a periodic
line, not as a discrete event.** A finality-stall detection is therefore
"`finalized_epoch` has not advanced in N minutes", which is a comparison across
successive heartbeats — the same absence-of-progress shape as OPS-002, and it
has the same limitation (a query cannot express "did not change").

**Reorgs.** Covered in detail in section 5; four clients, four message strings,
three different names for depth.

**Slashing.** Lighthouse logs observed slashings at `crit!` with `root_1`,
`root_2`, `slot`, `validator`, `src` (`gossip` / `api` / `block`), and its
slashing-protection database refuses with `DoubleBlockProposal`, `DoubleVote`,
`PrevSurroundsNew`, `NewSurroundsPrev` **[V]**.

### 2.2 Proposed `blockchain.*` fields for the node

ECS has no blockchain fieldset (section 5), so this is a custom extension. Rule
followed: **every field is named after a concept at least two real clients log,
and is tagged with what it maps from.** Fields marked **[I]** are inferences —
sensible, but not observed as a discrete field in a client log line.

| Field | Type | Grounded in | Tag |
|---|---|---|---|
| `blockchain.chain.id` | keyword | `eth_chainId` RPC method; not seen in a log line | **[I]** |
| `blockchain.network.name` | keyword | client `--network` flags | **[I]** |
| `blockchain.slot` | long | LH `slot`/`current_slot`, Prysm `slot`, Nimbus `slot` | **[V]** |
| `blockchain.epoch` | long | LH `epoch`, Prysm `sourceEpoch`/`targetEpoch` | **[V]** |
| `blockchain.head.slot` | long | LH `head_slot` | **[V]** |
| `blockchain.block.height` | long | Geth `number` | **[V]** |
| `blockchain.block.hash` | keyword | Geth `hash`, LH `new_head`/`head_block`, Prysm `newRoot`/`blockRoot` | **[V]** |
| `blockchain.block.parent_hash` | keyword | Prysm `commonAncestorRoot` (reorg context) | **[V]** partial |
| `blockchain.finalized.epoch` | long | LH `finalized_epoch` | **[V]** |
| `blockchain.finalized.root` | keyword | LH `finalized_root` | **[V]** |
| `blockchain.justified.epoch` | long | consensus spec `current_justified_checkpoint` | **[I]** — spec concept, not seen as a log field |
| `blockchain.reorg.depth` | long | Geth `drop`, LH `reorg_distance`, Prysm `depth` | **[V]** |
| `blockchain.reorg.added` | long | Geth `add`, Prysm `distance` | **[V]** |
| `blockchain.validator.index` | long | LH `index`, `validator` | **[V]** |
| `blockchain.validator.pubkey` | keyword | Prysm `pubkey` | **[V]** |
| `blockchain.duty.type` | keyword | derived from message string in every client | **[I]** — no client emits this as a field |
| `blockchain.duty.outcome` | keyword | derived from message string (`performed`/`missed`/`refused`) | **[I]** |
| `blockchain.attestation.source_epoch` | long | Prysm `sourceEpoch` | **[V]** |
| `blockchain.attestation.target_epoch` | long | Prysm `targetEpoch` | **[V]** |
| `blockchain.attestation.committee_index` | long | Prysm `committeeIndex` | **[V]** |
| `blockchain.peer.count` | long | LH `peer_count` / `peers` | **[V]** |
| `blockchain.peer.id` | keyword | libp2p concept; not observed in the lines consulted | **[I]** |
| `blockchain.sync.distance` | long | LH `head_slot` vs `current_slot` on the status line | **[I]** — derived, not logged directly |
| `blockchain.rpc.method` | keyword | Geth `"Served "+msg.Method` | **[V]** |
| `blockchain.rpc.namespace` | keyword | derived by splitting the method on `_` | **[I]** |
| `blockchain.rpc.batch_size` | long | Geth `--rpc.batch-request-limit` caps it | **[I]** |
| `blockchain.rpc.block_range` | long | Besu `--rpc-max-logs-range` caps it | **[I]** |

Two deliberate omissions. **Signatures** — Prysm logs the attestation
`signature`, but there is no analytical use for it and it is unbounded
high-cardinality; leave it out, or route it through the redaction stage in
`40-enrich.conf` the way bearer tokens already are **[I]**. **Validator public
keys as a primary key** — prefer `blockchain.validator.index` for aggregation
(it is a compact integer) and carry the pubkey only where a client would.

`blockchain.duty.type` and `blockchain.duty.outcome` deserve a note: **no real
client emits these as fields.** They exist only as English in message strings.
Inventing them is the single biggest normalization win available — it is what
turns four clients' worth of prose into one aggregatable pair of keywords, and
it is exactly the move `30-normalize.conf` already makes for `log.level` and
`http.response.status_class`.

### 2.3 What the node should emit, concretely

Four datasets, routed by `event.dataset` in `90-output.conf` as usual.

| Dataset | Cadence | Carries | Models |
|---|---|---|---|
| `ethereum.rpc` | per request | `blockchain.rpc.*`, `source.ip`, `http.*`, `event.outcome` | the reverse-proxy access log in front of 8545 |
| `ethereum.consensus` | per slot | `blockchain.slot`, `.epoch`, `.head.slot`, `.finalized.*`, `.peer.count`, `.sync.distance` | Lighthouse's `"Synced"` notifier line |
| `ethereum.duty` | per duty | `blockchain.duty.*`, `.validator.index`, `.slot`, `.attestation.*` | Lighthouse validator monitor / Prysm attest+propose |
| `ethereum.chain` | per event | `blockchain.block.*`, `blockchain.reorg.*` | Geth `"Chain reorg detected"` / LH `"Beacon chain re-org"` |

`ethereum.consensus` is the one to get right first. It is a heartbeat, so it
gives the demo the same property the existing `logstash.heartbeat` dataset
gives the pipeline: a known-good signal whose silence is itself an alert, and a
carrier for slowly-changing state (finalized epoch, peer count) that can be
diffed across successive documents.

Retention should follow the existing split rather than inventing a third tier:
`ethereum.rpc` and `ethereum.duty` are security-relevant (90d);
`ethereum.consensus` and `ethereum.chain` are operational (14d) **[I]**. The
consistency test that checks "a security dataset matches a security index
pattern" will enforce it.

### 2.4 Alert versus merely log

The most useful evidence here is **the log level the client's own authors
chose**. A team that writes `crit!` has told you they consider it pageable.
Everything in this table is a verified level from client source; the alerting
verdict is inference from it **[I]**.

| Signal | Client level | Verdict | Rule shape |
|---|---|---|---|
| Slashing-protection refusal (`DoubleVote`, `DoubleBlockProposal`, `PrevSurroundsNew`) | Prysm logs the check failure explicitly | **Page.** One occurrence. The signer was asked to do something slashable | `query` |
| Slashing observed on chain (`"Proposer slashing"`, `"Attester slashing"`) | Lighthouse `crit!` — its highest level | **Page.** One occurrence | `query` |
| Missed block proposal (`"Validator missed a block"`) | Lighthouse `error!` | **Page.** Proposals are rare and individually valuable | `query` |
| Deep reorg | Geth escalates `Info`→`Warn` at `len(oldChain) > 63` | **Page** above the client's own boundary | `query` on `blockchain.reorg.depth >= 64` |
| Low peer count (`"Low peer count"`) | Lighthouse `warn!` | **Alert, not page.** Recovers on its own; alert on sustained | `threshold` over a window |
| Finality not advancing | not logged as an event at all | **Page.** But needs absence-of-progress semantics — same limitation as OPS-002 | Watcher or ES\|QL, not a query rule |
| Missed attestation (`"Previous epoch attestation missing"`) | Lighthouse `warn!` | **Rate only.** Individual misses are normal background; alert on a *rate* or on correlation across many validator indices | `threshold` + cardinality |
| Attestation head/target mismatch | Lighthouse `warn!` | **Dashboard.** Diagnostic for the above, not independently actionable | — |
| Shallow reorg (1–2 blocks) | Geth `Info`, Lighthouse `info!` | **Log only.** Routine | — |
| Successful attestation / proposal | `info!` | **Log only.** The denominator for every rate above | — |
| Per-slot `"Synced"` status | `info!` | **Log only — but its absence pages.** | inverted-condition rule |
| Privileged RPC namespace from a public IP | Geth logs nothing usable | **Page.** See section 3 | `query` |

The pattern worth internalising, and the thing that should shape the demo: in
this domain **the high-severity events are single-occurrence `query` rules, not
threshold rules.** That is the opposite of the existing rule set, where the
interesting work is all in thresholds and cardinality. A slashing-protection
refusal happening *once* is a worse signal than ten thousand failed logins.
Thresholds re-enter for the liveness side — missed-duty rates, sustained low
peers — and correlation (many validator indices failing at once) is where
SEC-002's cardinality shape transfers directly, because the consensus spec's
correlated-slashing penalty means simultaneity is precisely what makes an
incident expensive (section 6).

---

## 3. Direction 1 — JSON-RPC node endpoint security

### What the clients actually do by default

Geth binds HTTP-RPC to the loopback interface and enables only three
namespaces:

> "Geth falls back to its default behaviour of accepting connections from the
> local loopback interface (127.0.0.1)" — default port 8545. "Not all of the
> JSON-RPC method namespaces are enabled for HTTP requests by default. Instead,
> they have to be whitelisted explicitly." Only `eth`, `net` and `web3` are on.

Source: <https://geth.ethereum.org/docs/interacting-with-geth/rpc> **[V]**

The same page says exposing the dangerous namespaces over HTTP is "**not
recommended** because access to these methods increases the attack surface",
and — the line that matters for this project — that "**there are bots that
continually scan for http-enabled Ethereum nodes to attack**" **[V]**.

So the insecure configuration is not the default. It is something operators do
to themselves, usually by setting `--http.addr 0.0.0.0` and a wide
`--http.api`. Geth still ships `--allow-insecure-unlock`, documented as "Allow
insecure account unlocking when account-related RPCs are exposed by http
(deprecated)", and the `personal` namespace is deprecated in favour of Clef,
whose entire design point is replacing "indiscriminate locking and unlocking of
accounts" with per-action approval.

Sources:
<https://geth.ethereum.org/docs/fundamentals/command-line-options>,
<https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-personal> **[V]**

Besu is the same picture: `--rpc-http-authentication-enabled` defaults to
`false` in source (`JsonRpcHttpOptions.java`) **[V]**.

Source:
<https://github.com/besu-eth/besu/blob/main/app/src/main/java/org/hyperledger/besu/cli/options/JsonRpcHttpOptions.java>

### There is no authentication in the spec

The Ethereum execution API specification defines authentication only for the
`engine` namespace, on a separate port, and says so explicitly:

> "The `engine` JSON-RPC interface, exposed by execution layer clients and
> consumed by consensus layer clients, needs to be authenticated. The
> authentication scheme chosen for this purpose is JWT. The type of attacks
> that this authentication scheme attempts to protect against are the
> following: RPC port exposed towards the internet […]"
>
> "The execution layer client **MUST** expose the authenticated Engine API at a
> port independent from existing JSON-RPC API. The default port for the
> authenticated Engine API is `8551`."

Source:
<https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md>
**[V]**

The corollary — that the public JSON-RPC namespaces on 8545 have no
specification-level authentication or authorization concept — follows directly
and is why network controls and monitoring are the only layer available **[I]**.

### The documented attack

The strongest primary source is Zhou et al., *Towards a First Step to
Understand the Cryptocurrency Stealing Attack on Ethereum* (RAID 2019), which
ran a purpose-built honeypot ("Siren") on port 8545 for six months:

- approximately **1,000 of 15,560** public Ethereum nodes were found vulnerable
  (~7%)
- **308.66 million RPC requests** captured from **1,072 distinct IP addresses**
- **36 attacker groups** using **59 distinct Ethereum accounts**
- estimated profit **$18.56M**, of which **$583,956** was traced to directly
  captured malicious accounts
- a single source IP (89.144.25.28) accounted for **101.73 million requests**,
  33% of the total
- attackers polled transaction methods at "**nearly 50 requests per second**",
  waiting for an account to be unlocked
- dictionary attacks with "**more than 600 weak passwords**" against
  `personal_unlockAccount`
- gas prices **15 to 4,500 times** normal, to get the theft mined first
- two groups targeted **161 different ERC20 tokens** with zero-gas transactions

Source: <https://arxiv.org/abs/1904.01981> **[V]**

The paper also documents the method sequence, which is what makes this
detectable rather than merely alarming:

| Stage | Methods | Observed volume |
|---|---|---|
| 1. Reconnaissance | `eth_blockNumber`, `web3_clientVersion`, `net_version` | 27M / 4.5M / 4.8M |
| 2. Enumeration | `eth_accounts`, `eth_getBalance`, `eth_gasPrice` | 27M / 93.5M / 63K |
| 3. Execution | `eth_sendTransaction`, `eth_signTransaction` | — |

`eth_accounts` at 27 million requests is the signal. A legitimate dapp backend
polling a node has no reason to call `eth_accounts` repeatedly; a scanner
enumerating unlockable keys calls nothing else. That is a per-source-IP
threshold on a single method name, which is the same rule shape as SEC-003.

The widely-cited 2018 figure — **38,642 ETH, ~$20.5M**, attributed by Qihoo 360
Netlab to a single group mass-scanning port 8545 — I could only reach through
secondary reporting; the Netlab post itself was not retrievable. Treat the
number as **[S]** unless someone recovers the original.
(Secondary: <https://www.bleepingcomputer.com/news/security/hackers-stole-over-20-million-from-misconfigured-ethereum-clients/>)

### Is HTTP-log-based detection a recognized mitigation?

Not really, and this is the honest gap. The Geth documentation's mitigation is
configuration (do not expose the namespaces, do not unlock accounts, use Clef)
and network placement, not detection. I found no official client documentation
recommending RPC access-log analysis as a control **[V — verified absence in
the pages consulted; not an exhaustive search]**.

What I did verify is that the clients make detection hard by default, which is
an argument for putting a proxy in front:

In `rpc/handler.go`, Geth logs a served call as:

```go
h.log.Warn("Served "+msg.Method, logctx...)   // when resp.Error != nil
h.log.Debug("Served "+msg.Method, logctx...)  // on success
```

with `logctx` containing only `reqid`, `duration`, and on failure `err` /
`errdata`. Default `--verbosity` is 3 (info), so **successful RPC calls are not
logged at all by default**, and even at debug level **the client IP is absent
from the log line**. Geth does have the address — `rpc/http.go` builds
`PeerInfo{Transport: "http", RemoteAddr: r.RemoteAddr}` — it simply is not put
in the log context.

Sources:
<https://github.com/ethereum/go-ethereum/blob/master/rpc/handler.go>,
<https://github.com/ethereum/go-ethereum/blob/master/rpc/http.go> **[V]**

**Verdict: strong fit, and the best of the seven.** The detection substrate is
an HTTP access log with a method name in it, which this pipeline already
handles end to end. The new work is small and named in section 10. The caveat to
state plainly: the *signal* has to be produced by a reverse proxy, because the
node will not produce it.

---

## 4. Direction 2 — JSON-RPC resource exhaustion

Real, documented, and cheaper to fix by configuration than by monitoring.

Besu carries a CLI option specifically for it, defined in source as:

```java
@CommandLine.Option(
    names = {"--rpc-max-logs-range"},
    description = "Specifies the maximum number of blocks to retrieve logs from
                   via RPC. Must be >=0. 0 specifies no limit (default: ${DEFAULT-VALUE})")
private final Long rpcMaxLogsRange = 5000L;
```

Source:
<https://github.com/besu-eth/besu/blob/main/app/src/main/java/org/hyperledger/besu/cli/options/ApiConfigurationOptions.java>
**[V]**

The issue that created it states the problem directly:

> "`eth_getLogs` default `fromBlock` from value is the genesis block. This leads
> to large default queries that can block the client."

Source: <https://github.com/besu-eth/besu/issues/4563> **[V]**

Geth caps the adjacent surfaces: `--rpc.gascap` 50,000,000, `--rpc.evmtimeout`
5s, `--rpc.batch-request-limit` 1000, `--rpc.batch-response-max-size`
25,000,000 **[V]**
(<https://geth.ethereum.org/docs/fundamentals/command-line-options>). It does
*not* cap `eth_getLogs` block range, and issue #28765 reports a single
`eth_getLogs` over blocks `0x0`–`0x120dc53` (~18 million blocks) timing out on
Geth v1.13.5 **[V]** (<https://github.com/ethereum/go-ethereum/issues/28765>).

Commercial providers price the disparity rather than block it. Alchemy's
published compute-unit table **[V]**
(<https://www.alchemy.com/docs/reference/compute-unit-costs>):

| Method | CU |
|---|---|
| `eth_blockNumber` | 10 |
| `eth_getBalance` | 20 |
| `eth_getBlockByNumber` | 20 |
| `eth_call` | 26 |
| `debug_traceTransaction` | 40 |
| `trace_transaction` | 40 |
| `eth_getLogs` | 60 |

**Verdict: real but weak fit as a *security* use case.** Besu's fix is one flag.
Where it becomes worth doing is as a *cost and capacity* dataset — "which
source IP or API key burned the most compute units this week" is a legitimate
aggregation, and it rides on the same access log as direction 1 for almost no
extra cost. Treat it as a cheap add-on to use case 1, not a use case of its own.

One honest limitation: the block range of an `eth_getLogs` call lives in the
JSON-RPC **request body**, not the URL. An nginx access log does not contain
request bodies. Capturing `fromBlock`/`toBlock` requires either a proxy
configured to log the body, or instrumentation inside the node. That is real
work and it is called out in section 10.

---

## 5. Direction 3 — the log format fragmentation problem

This was the hypothesis most worth testing, and it holds.

### Is there a common schema? No.

ECS ships 53 fieldset definitions. None is blockchain-related:

```
agent as base client cloud code_signature container data_stream destination
device dll dns ecs elf email entity entity_reference error event faas file
gen_ai geo group hash host http interface log macho network observer
orchestrator organization os package pe process registry related risk rule
server service source threat tls tracing url user user_agent vlan volume
vulnerability x509
```

Source: <https://github.com/elastic/ecs/tree/main/schemas> **[V]**

A GitHub search of `elastic/ecs` for "blockchain" across issues and pull
requests returns **zero results** **[V]**. There is no proposal, no RFC, no
rejected attempt. The field space is empty.

### Does each client offer structured output?

| Client | Layer | Native JSON log output | Source |
|---|---|---|---|
| Geth | execution | **Yes** — `--log.format json\|logfmt\|terminal` | [CLI options](https://geth.ethereum.org/docs/fundamentals/command-line-options) **[V]** |
| Nethermind | execution | **No** native option; NLog via `NLog.config` / `--logger-config` | [docs](https://docs.nethermind.io/fundamentals/logs/) **[V]** |
| Besu | execution | **No** native option; requires a custom `LOG4J_CONFIGURATION_FILE` | [docs](https://docs.besu-eth.org/public-networks/how-to/monitor/logging) **[V]** |
| Erigon | execution | Not verified — see section 11 | — **[S]** |
| Lighthouse | consensus | **Yes** — `--log-format JSON`, `--logfile-format DEFAULT\|JSON` | [book](https://lighthouse-book.sigmaprime.io/help_bn.html) **[V]** |
| Prysm | consensus | **Yes** — `--log-format text\|json\|fluentd\|journald` | [docs](https://prysm.offchainlabs.com/docs/prysm-usage/parameters) **[V]** |
| Teku | consensus | **No** — open feature request, PR closed unmerged | [issue #10247](https://github.com/Consensys-Incorporated/teku/issues/10247) **[V]** |
| Nimbus | consensus | **Yes** — `--log-format auto\|colors\|nocolors\|json` | [`conf.nim`](https://github.com/status-im/nimbus-eth2/blob/stable/beacon_chain/conf.nim) **[V]** |
| Lodestar | consensus | **Yes**, but the option is marked `hidden: true` — `--logFormat human\|json` | [`logOptions.ts`](https://github.com/ChainSafe/lodestar/blob/unstable/packages/cli/src/options/logOptions.ts), [`interface.ts`](https://github.com/ChainSafe/lodestar/blob/unstable/packages/logger/src/interface.ts) **[V]** |

### Is "I cannot correlate mixed-client logs" a real complaint? Yes.

Teku issue #10247, opened 2025-12-17 and **still open**:

> "To simplify log analysis across different monitoring stacks, please add an
> option to output logs in JSON format. While `LOG4J_CONFIGURATION_FILE` allows
> for custom log configurations, it is a bit of an overhead for most users.
> Proposed Changes: Add a CLI flag `--log-format=json`"

Source: <https://github.com/Consensys-Incorporated/teku/issues/10247> **[V]**

A pull request implementing exactly that, using Log4j's `JsonTemplateLayout` —
"This makes Teku logs easier to ingest in log analysis and monitoring systems
without requiring users to provide a custom Log4j configuration" — was closed
**unmerged** (`merged: false`).
Source: <https://github.com/Consensys-Incorporated/teku/pull/10864> **[V]**

The same request has a long history in Lighthouse (issues #374, #740, PRs #389,
#414, #1485) and in Geth (issues #222, #538, PR #546) — in those cases
eventually implemented **[V]**.

### JSON is not the same as a schema

This is the part that matters and is easy to miss. Even where JSON output
exists, the keys are per-client.

Geth's JSON handler rewrites the standard `slog` keys:

```go
case slog.TimeKey:  return slog.Attr{Key: "t", Value: attr.Value}
case slog.LevelKey: attr = slog.Any("lvl", LevelString(l))
```

Source: <https://github.com/ethereum/go-ethereum/blob/master/log/handler.go> **[V]**

So Geth JSON is `{"t":…,"lvl":…,"msg":…}` — not `@timestamp`, not `log.level`,
not `message`. Every downstream consumer writes its own mapping.

The divergence is far worse for domain fields. Here is **one event** — a chain
reorganisation — as four clients log it, all verified from source:

| Client | Message | Fields |
|---|---|---|
| Geth | `"Chain reorg detected"`, escalating to `"Large chain reorg detected"` at `len(oldChain) > 63` | `number`, `hash`, `drop`, `dropfrom`, `add`, `addfrom` |
| Lighthouse | `"Beacon chain re-org"` | `previous_head`, `previous_slot`, `new_head`, `new_slot`, `reorg_distance` |
| Prysm | `"Chain reorg occurred"` | `oldSlot`, `oldRoot`, `oldWeight`, `newSlot`, `newRoot`, `newWeight`, `commonAncestorRoot`, `distance`, `depth` |
| Nimbus | `"Updated head block with chain reorg"` | (chronicles key/value) |

Sources:
[go-ethereum `core/blockchain.go`](https://github.com/ethereum/go-ethereum/blob/master/core/blockchain.go),
[lighthouse `canonical_head.rs`](https://github.com/sigp/lighthouse/blob/stable/beacon_node/beacon_chain/src/canonical_head.rs),
[prysm `beacon-chain/blockchain/head.go`](https://github.com/OffchainLabs/prysm/blob/develop/beacon-chain/blockchain/head.go),
[nimbus `blockchain_dag.nim`](https://github.com/status-im/nimbus-eth2/blob/stable/beacon_chain/consensus_object_pools/blockchain_dag.nim) **[V]**

Three different names for reorg depth (`drop`, `reorg_distance`, `depth`), two
casing conventions, four different message strings. A dashboard panel that
charts "reorg depth over time" across a mixed-client fleet has to know all
three, and adding a fifth client means editing it. That is the exact argument
`docs/architecture.md` makes for ECS, restated in a domain where nobody has
made it yet.

**Verdict: strongest conceptual fit in the list.** It is also the one where the
project's existing artefact — a normalize stage that maps source-specific
fields onto a shared vocabulary — is literally the deliverable rather than an
analogy for it.

---

## 6. Direction 4 — validator slashing and liveness

### The slashing conditions, from the spec

A validator is slashable for two things.

**Proposer slashing** — two distinct signed beacon block headers for the same
slot by the same proposer.

**Attester slashing** — `is_slashable_attestation_data`, defined in
`specs/phase0/beacon-chain.md` as a *double vote* (two different attestations
for the same target epoch) or a *surround vote* (one attestation's source/target
span strictly surrounds another's).

Source:
<https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md> **[V]**

### What it costs

Phase 0 presets **[V]**:

| Constant | Value |
|---|---|
| `MIN_SLASHING_PENALTY_QUOTIENT` | `2**7` = 128 |
| `WHISTLEBLOWER_REWARD_QUOTIENT` | `2**9` = 512 |
| `PROPORTIONAL_SLASHING_MULTIPLIER` | 1 (initial mainnet value) |

Electra revises these **[V]**:

| Constant | Value |
|---|---|
| `MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA` | `2**12` = 4,096 |
| `WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA` | `2**12` = 4,096 |

The immediate penalty is `validator.effective_balance //
MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA` — for a 32 ETH validator, **0.0078125
ETH** **[V, arithmetic]**. The immediate penalty is therefore *not* the cost. The
cost is the forced exit, the correlation penalty applied mid-way through the
withdrawable period scaled by the total balance slashed in the surrounding
window, and the forgone rewards for the exit queue duration **[I]**. I did not
trace the `PROPORTIONAL_SLASHING_MULTIPLIER` value through every fork; see
section 11.

The economic point that makes this monitorable: the correlation penalty means a
*correlated* slashing — many validators of one operator, at once — is
qualitatively worse than an isolated one **[I, from the spec's
`PROPORTIONAL_SLASHING_MULTIPLIER` mechanic]**. That is a cardinality-over-time
detection, which is exactly the SEC-002 rule shape.

### What appears in the logs

Lighthouse's beacon node logs observed slashings at `crit!`, its highest level:

```rust
crit!(%root_2, %root_1, %slot, validator = %id, src, "Proposer slashing");
crit!(%epoch, slot = %data.slot, validator = %id, src, "Attester slashing");
```

with `src` distinguishing `"gossip"`, `"api"` or `"block"` — i.e. whether the
node saw the slashing on the network or included in a block. Source:
<https://github.com/sigp/lighthouse/blob/stable/beacon_node/beacon_chain/src/validator_monitor.rs> **[V]**

Before a slashing, the validator client's own slashing-protection database is
the last line of defence, and its refusals are the highest-value log event in
the whole domain. Lighthouse's database returns
`DoubleBlockProposal`, `DoubleVote`, `PrevSurroundsNew`, `NewSurroundsPrev`
**[V]**
(<https://github.com/sigp/lighthouse/blob/stable/validator_client/slashing_protection/src/slashing_database.rs>).
Prysm logs `"Failed block slashing protection check"`,
`"Failed attestation slashing protection check"` and
`"Attempted slashable attestation details"` **[V]**
(<https://github.com/OffchainLabs/prysm/blob/develop/validator/client/propose.go>,
<https://github.com/OffchainLabs/prysm/blob/develop/validator/client/attest.go>).

A slashing-protection refusal means the signer was *asked* to sign something
slashable and said no. On correct infrastructure that should never happen. It is
the single best alert in this domain and it is a `query` rule, not a threshold
rule — one occurrence is the alert.

For liveness, Lighthouse's validator monitor logs per-duty outcomes:
`"Validator missed a block"` (`error!`, with `index` and `slot`),
`"Previous epoch attestation missing"` (`warn!`),
`"Attestation failed to match head"`, `"Attestation failed to match target"`,
`"Potential sub-optimal inclusion delay"` **[V]**, same file as above.

### The documented infrastructure-error slashing

On 2 February 2021, **75 validators run by Staked were slashed**, the largest
single slashing event on the beacon chain at that time. Reported cause: the
operator disabled persistence of Prysm's on-client slashing-protection
database while tuning for attestation performance; nodes then restarted and
re-signed blocks they had already signed.

The first-party post-mortem (`blog.staked.us/blog/eth2-post-mortem`) now
**301-redirects to `kraken.com/institutions/staking`** and the content is gone.
I therefore have this only through secondary reporting and mark it **[S]** on
the details, **[V]** only on the fact that the first-party URL no longer
resolves. Secondary:
<https://www.theblock.co/post/93730/eth2-validators-slashed-staked-bug>,
<https://cointelegraph.com/news/expensive-lesson-75-eth2-validators-slashed-for-introducing-potential-chain-split-bug>

The mechanism it illustrates — the same keys signing from two places, or a
protection database that does not survive a restart — is the canonical
infrastructure failure in staking. I could not find a *first-party* post-mortem
of the "same keys on two machines during failover" case; see section 11.

**Verdict: real pain, good fit, but it is a liveness/ops use case more than a
security one.** The signals are log lines with stable message strings and
structured fields; the detections are one `query` rule (protection refusal) and
two threshold rules (missed duties rate, correlated slashing). The honest
caveat: most serious staking operators already watch this through Prometheus
metrics exported by the clients, not through logs. Logs add the *why* — which
validator index, which slot, which source — that a counter does not carry
**[I]**.

---

## 7. Direction 5 — remote signer access monitoring (Web3Signer)

Short section, disproportionately good fit.

Web3Signer's `--logging-format` accepts `PLAIN`, `ECS`, `GCP`, `LOGSTASH`,
`GELF`; the documentation describes the structured formats as emitting "each
log record as a JSON object in a well-defined format, making logs consistent
and machine-readable". Source:
<https://docs.web3signer.consensys.io/how-to/monitor/logging> **[V]**

**It speaks ECS natively.** That is not a coincidence worth being cute about —
it means this platform's `20-parse.conf` application-JSON path ingests
Web3Signer output with zero new parsing, and the normalize/enrich/redact/route
stages apply unchanged.

Access controls and their defaults, from the CLI reference
(<https://docs.web3signer.consensys.io/reference/cli/options>) **[V]**:

| Option | Default | Note |
|---|---|---|
| `--access-logs-enabled` | `false` | the signing-request access log is **off by default** |
| `--http-host-allowlist` | `localhost`, `127.0.0.1` | |
| `--tls-allow-any-client` | `false` | |
| `--tls-known-clients-file` | — | client auth by CN + SHA-256 fingerprint |

An off-by-default access log on the component that holds validator signing keys
is the same class of finding as an unlogged RPC port. Turning it on and shipping
it is a genuine control.

**Verdict: good fit, small scope.** Best framed as a component of the validator
use case rather than standing alone — a signer with no traffic pattern of its
own is not interesting; a signer whose request rate, source, or requested
validator set changes is.

---

## 8. Directions 6 and 7 — ruled out, briefly

Recorded so the decision is not re-litigated. Neither is being built.

### Direction 6 — on-chain / smart-contract event monitoring

Forta, OpenZeppelin Defender Sentinel and Tenderly Alerts watch transactions
and contract events and fire on conditions expressed over chain state.

**Architecturally this does not fit, and the mismatch is at the ingestion
layer.** This platform's entire collection model is: a container writes to
stdout, the runtime writes that to `/var/log/containers/*.log`, a DaemonSet
agent reads the file and ships it. On-chain events are not in a file. Getting
them means a process that polls `eth_getLogs` or holds a WebSocket
subscription, tracks its own cursor across restarts, handles reorgs by
retracting already-emitted events, and decodes ABI-encoded topics into fields.

That is a new first-class component — a stateful chain indexer — not a parser.
It also breaks the property `README.md` calls out deliberately: the monitored
workload currently has **zero network egress** because its logs leave via
stdout. A poller needs outbound network to an RPC endpoint by definition.

Reorg handling alone makes it materially harder than it looks: an event
"observed" at block N may be un-observed at block N+2, and the content-hash
`_id` idempotency in `30-normalize.conf` makes duplicates harmless but does not
give you retraction **[I]**.

**Verdict: bad fit. Do not build.** Estimated work is a new service plus a new
ingestion path plus reorg-aware state, which is comparable to the size of the
existing pipeline.

### Direction 7 — bridge exploits: infrastructure vs contract layer

The distinction is the only thing that matters here, and it splits cleanly.

| Incident | Loss | Layer | Basis |
|---|---|---|---|
| Ronin (Mar 2022) | 173,600 ETH + 25.5M USDC | **Infrastructure** — spearphish, 5 of 9 validator keys, abuse of an unrevoked Axie DAO allowlist via a "gas-free RPC node"; undetected six days | **[S]** — first-party post-mortem URLs now 404 (see §11) |
| Harmony Horizon (Jun 2022) | ~$100M | **Infrastructure** — 2-of-5 multisig, encrypted keys decrypted by the attacker | **[S]** — first-party Medium post returned 403 |
| Wormhole (Feb 2022) | ~120,000 wETH, ~$326M | **Contract** — `load_instruction_at` did not verify the instructions sysvar account; guardian signatures never actually checked | **[S]** |
| Nomad (Aug 2022) | ~$190M | **Contract** — trusted root initialized to `0x00`, making every unproven message valid | **[S]** |

The pattern is genuinely interesting: **two of the four largest bridge losses
were infrastructure compromises, not contract bugs** — stolen keys and a
compromised signing path, which is SIEM territory — and two were logic bugs a
SIEM would never have seen. That is a real argument in the abstract.

**It is not an argument for this project.** Detecting the Ronin compromise would
have required visibility into Sky Mavis's internal corporate endpoints, their
validator hosts, and the authorization state of an allowlist in another
organisation. Those are the *inputs* a SIEM needs, and having a SIEM does not
produce them. The honest statement is: this platform is the kind of thing that
would have been part of the answer, alongside EDR, key ceremony discipline and
access review, and claiming more than that would be marketing.

**Verdict: cite as motivation, build nothing for it.** Per the direction given,
budget was not spent verifying these to primary-source standard, and every row
above is tagged accordingly.

---

## 9. Ranked table

| # | Use case | Pain evidence | Architectural fit | Work to support |
|---|---|---|---|---|
| 1 | **JSON-RPC endpoint security** — namespace exposure, account enumeration, unlock brute force | 308M requests / 1,072 IPs / $18.56M in a 6-month honeypot; ~7% of public nodes vulnerable; spec has no auth for public namespaces; Geth docs confirm bots scan continuously | **High.** HTTP access log + per-source-IP threshold + cardinality = SEC-001/SEC-003 rule shapes reused verbatim. Needs a reverse proxy because Geth logs no client IP | **Small.** 1 grok pattern (RPC access log), ~6 new fields, 4 new rules |
| 2 | **Client log schema normalization** | No blockchain fieldset in ECS and zero issues on it; 4 of 9 clients have no JSON output; verified field-name divergence for the same event across Geth/Lighthouse/Prysm/Nimbus; open Teku request, PR closed unmerged | **Highest conceptually.** `30-normalize.conf` is literally the deliverable. Zero architectural change | **Medium.** A `blockchain.*` field definition, per-client grok/rename maps, index template additions |
| 3 | **Validator duty + slashing-protection monitoring** | Spec-defined slashing conditions; clients log refusals and slashings at `error!`/`crit!`; documented 75-validator operator slashing from a disabled protection DB | **Good.** Message-string `query` rules and duty-miss threshold rules. Existing severity scoring applies | **Medium.** Grok/JSON field maps per consensus client, 3–4 new rules |
| 4 | **Remote signer (Web3Signer) access monitoring** | Access log ships **disabled by default** on the component holding signing keys | **High but narrow.** Emits ECS natively — zero parser work | **Very small.** Config change + 2 rules |
| 5 | **RPC resource exhaustion / cost** | Besu `--rpc-max-logs-range` (default 5000) exists because unbounded `eth_getLogs` "can block the client"; 18M-block query timeout in Geth #28765; 6x CU spread between methods | **Partial.** Method name is in the access log; block range is in the request *body*, which an access log does not capture | **Small if method-only; large if range-aware** |
| 6 | **Bridge/protocol exploit detection** | 2 of 4 largest bridge losses were infrastructure-layer | **Poor for this project.** Requires endpoint, host and IAM telemetry this platform does not collect | **Out of scope** |
| 7 | **On-chain event monitoring** | Real product category (Forta, Defender, Tenderly) | **Bad.** Needs an RPC poller with reorg-aware cursor state — a different ingestion path entirely, and it breaks the zero-egress property | **Large — do not build** |

---

## 10. What would actually have to be built

For the top two use cases, against the existing pipeline.

### 10.1 Use case 1 — JSON-RPC endpoint security

**Ingestion path.** Unchanged in shape. Put nginx in front of the node's RPC
port and extend its log format with the JSON-RPC method, which nginx can extract
from the request body:

```nginx
log_format rpc '$remote_addr - $remote_user [$time_local] "$request" '
               '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
               'rt=$request_time rid=$request_id '
               'rpcmethod=$rpc_method rpcbatch=$rpc_batch_size';
```

`$rpc_method` has to come from body inspection — the practical options are an
`njs` handler or a small purpose-built proxy. **Naming the cost honestly: this
is the single largest piece of new work in use case 1**, because stock nginx
cannot read a JSON request body into a log variable without a scripting module.

**New grok pattern.** `logstash/patterns/ethereum` — one pattern, a superset of
the existing nginx pattern with `rpcmethod=` and `rpcbatch=` appended. The
existing combined-log fallback in `20-parse.conf` stays as the second
alternative, so an un-extended nginx still parses.

**New normalize logic in `30-normalize.conf`:**

- derive `blockchain.rpc.namespace` from the method prefix by splitting on `_`
  (`personal_unlockAccount` → `personal`)
- set `event.dataset` to `ethereum.rpc`
- floor `event.severity` at 80 when `blockchain.rpc.namespace` is one of
  `admin`, `personal`, `debug`, `miner` — the same "an INFO line from a known-bad
  source is not an INFO event" principle already applied to threat-intel hits

**New detection rules** (`kibana/detections/detection-rules.json`, same JSON
shape, same required `false_positives` and `investigation_fields`):

| ID | Rule | Type | Condition | ATT&CK |
|---|---|---|---|---|
| CHAIN-001 | Privileged RPC namespace invoked from a public source | query | `blockchain.rpc.namespace:(admin or personal or debug or miner) and source.ip_scope:public` | T1190 |
| CHAIN-002 | RPC account enumeration | threshold | `blockchain.rpc.method:eth_accounts`, ≥50 per `source.ip` in 5m | T1087 |
| CHAIN-003 | Account unlock brute force | threshold | `blockchain.rpc.method:personal_unlockAccount and event.outcome:failure`, ≥10 per `source.ip` in 5m | T1110.001 |
| CHAIN-004 | RPC method sweep / fingerprinting | threshold | cardinality of `blockchain.rpc.method` ≥ 25 per `source.ip` in 10m | T1595 |

CHAIN-003 is SEC-001 with a different query and the same threshold semantics;
`tests/simulate_detections.py` already implements those semantics and will
evaluate it without modification. CHAIN-004 is SEC-003's cardinality shape.

**Index template.** `blockchain.rpc.method`, `blockchain.rpc.namespace` as
`keyword`; `blockchain.rpc.batch_size`, `blockchain.rpc.block_range` as `long`.
Mapping them is mandatory, not optional — `dynamic: false` means an unmapped
field never matches and the rule silently never fires, which is the exact bug
class `tests/test_platform_consistency.py` exists to catch.

**Retention.** `ethereum.rpc` is high-volume and security-relevant, which is a
genuine conflict with the current 90d-security / 14d-ops split. Recommendation:
its own ILM policy — 30 days hot for investigation, then delete **[I]**.

### 10.2 Use case 2 — client log normalization

**A `blockchain.*` field definition.** A YAML fieldset in the ECS custom-field
style, versioned in the repo, and the source of truth for the index template.
Proposed names with the client field each maps from — this is the whole value of
the use case, so the mapping table is the deliverable:

| Proposed field | Type | Geth | Lighthouse | Prysm | Status |
|---|---|---|---|---|---|
| `blockchain.chain.id` | keyword | — | — | — | **[I]** — from `eth_chainId`, not observed in a log line |
| `blockchain.block.height` | long | `number` | — | — | **[V]** |
| `blockchain.block.hash` | keyword | `hash` | `new_head` | `newRoot` | **[V]** |
| `blockchain.block.parent_hash` | keyword | — | — | `commonAncestorRoot` (reorg only) | **[V]** partial |
| `blockchain.slot` | long | n/a | `slot`, `new_slot` | `slot`, `newSlot` | **[V]** |
| `blockchain.epoch` | long | n/a | `epoch` | `sourceEpoch`/`targetEpoch` | **[V]** |
| `blockchain.reorg.depth` | long | `drop` | `reorg_distance` | `depth` | **[V]** |
| `blockchain.reorg.added` | long | `add` | — | `distance` | **[V]** partial |
| `blockchain.validator.index` | long | n/a | `index`, `validator` | — | **[V]** |
| `blockchain.validator.pubkey` | keyword | n/a | — | `pubkey` | **[V]** |
| `blockchain.attestation.source_epoch` | long | n/a | — | `sourceEpoch` | **[V]** |
| `blockchain.attestation.target_epoch` | long | n/a | — | `targetEpoch` | **[V]** |
| `blockchain.duty.type` | keyword | n/a | derived from message | derived from message | **[I]** — no client emits this as a field |
| `blockchain.duty.outcome` | keyword | n/a | derived from message | derived from message | **[I]** |
| `blockchain.peer.id` | keyword | — | — | — | **[I]** — not verified in any log line consulted |
| `blockchain.peer.count` | long | — | `peer_count`, `peers` | — | **[V]** |

Two entries deserve emphasis because they are the strongest evidence for the
whole use case: `blockchain.reorg.depth` maps from **three different field
names** and `blockchain.block.hash` from **three different field names**, all
verified from client source. That is the ECS argument in one row each.

**Per-client parse maps.** The pipeline needs a branch per client in
`20-parse.conf`, keyed off `service.name` (which the Kubernetes label rename
already populates):

- **Geth** — parse `--log.format json`, then rename `t`→`@timestamp`,
  `lvl`→`log.level`, `msg`→`message`. The existing level-normalization
  `translate` in `30-normalize.conf` already handles Geth's `warn`/`crit`
  vocabulary.
- **Lighthouse / Prysm / Nimbus / Lodestar** — JSON path, then per-client
  rename maps into `blockchain.*` per the table above.
- **Besu / Teku / Nethermind** — **no native JSON**, so these need grok against
  the pattern layout (Besu's default is
  `%d{yyyy-MM-dd HH:mm:ss.SSSZZZ} | %t | %-5level | %c{1} | %msg`). The existing
  `timeout_millis => 500` guard and the `parsed:none` catch-all dataset apply
  directly — and the "a rising unparsed count means a log format changed
  upstream" property becomes much more valuable here, because these are
  pattern-layout logs that will drift between client releases.

**Message-string matching is the fragile part, and it should be said out loud.**
`"Beacon chain re-org"` and `"Chain reorg occurred"` are not API surface. They
change without deprecation. Any rule that matches on them needs a test that
fails loudly when it stops matching — an extension of the existing consistency
suite, keyed on a fixture of captured real log lines per client version.

**New detection rules:**

| ID | Rule | Type | Condition |
|---|---|---|---|
| CHAIN-010 | Slashing protection refusal | query | `blockchain.duty.outcome:refused` — one occurrence is the alert |
| CHAIN-011 | Slashing observed on chain | query | message matches `Proposer slashing` or `Attester slashing` |
| CHAIN-012 | Correlated missed duties | threshold | ≥N missed duties with cardinality of `blockchain.validator.index` ≥ M in 2 epochs |
| CHAIN-013 | Deep reorg | query | `blockchain.reorg.depth >= 64` (Geth's own escalation boundary is `> 63`) |

CHAIN-013's threshold is not invented: Geth switches from `log.Info` to
`log.Warn` at `len(oldChain) > 63` **[V]**. Borrowing the client's own
escalation point is better than picking a number.

---

## 11. What I could not verify

Stated rather than papered over.

1. **The 38,642 ETH / $20.5M 2018 mass-theft figure.** Attributed to Qihoo 360
   Netlab by multiple secondary outlets. The Netlab blog post itself was not
   retrievable from this environment. The RAID 2019 honeypot paper is the
   primary source to lean on instead; do not cite the $20.5M as verified.

2. **The Staked.us February 2021 post-mortem.** `blog.staked.us/blog/eth2-post-mortem`
   **301-redirects to `kraken.com/institutions/staking`** — the first-party
   content is gone. The 75-validator count and the disabled-slashing-protection
   cause come from secondary reporting only.

3. **The Ronin and Harmony first-party post-mortems.** Both
   `roninchain.com/blog/posts/…` URLs return HTTP 404 when fetched directly,
   although a search index still surfaces their text; Harmony's official Medium
   post returned 403. Every Ronin and Harmony detail in section 8 is therefore
   **[S]**, including the "gas-free RPC node" mechanism and the six-day
   detection gap.

4. **Erigon's logging options.** I did not establish whether Erigon offers a
   native JSON log format flag. The table in section 5 marks it unverified.
   Someone should check `erigon --help` before that row is cited anywhere.

5. **`PROPORTIONAL_SLASHING_MULTIPLIER` across forks.** I verified the phase 0
   preset value (1) and the Electra min-penalty and whistleblower quotients
   (4,096 each). I did **not** trace the multiplier through Altair, Bellatrix
   and Electra, so the total correlated-slashing penalty for a given scenario is
   not computed here. Do not quote a total slashing cost from this document.

6. **Whether RPC access-log analysis is an officially recommended control.** I
   found no client documentation recommending it. That is a verified absence
   *in the pages I consulted*, not proof that no such guidance exists. The
   argument in section 3 rests on the attack being log-shaped, not on anyone
   official having said so.

7. **Teku's current state.** Issue #10247 was open and PR #10864 unmerged as of
   the data available to me. Re-check before relying on "Teku has no JSON
   logging" — this is precisely the kind of claim that expires.

8. **Nimbus and Lodestar reorg log field names.** I verified their *message
   strings* and their JSON-format flags from source, but did not enumerate their
   structured field keys the way I did for Geth, Lighthouse and Prysm. The
   section 10.2 table leaves those columns out rather than guessing.

9. **Whether a first-party post-mortem exists for the "same keys running on two
   machines during failover" slashing.** I looked and did not find one. The
   scenario is universally described in operator guidance, but I have no primary
   incident write-up for it.
