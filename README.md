# Sentinel — Cloud-Native Centralized Logging & Security Monitoring Platform

A centralized logging and security monitoring platform built on the Elastic
Stack. It collects logs from containerized workloads, normalizes them to a
common schema, enriches them with geographic and threat-intelligence context,
and runs version-controlled detection rules over the result.

It ships with its own monitored workloads — a web service and a working
proof-of-stake blockchain node — plus reproducible attack scenarios, so every
detection rule can be **demonstrated firing** rather than described.

```
17 detection rules   ·   194 automated tests   ·   16 attack scenarios   ·   3 dashboards
```

---

## Contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Repository layout](#repository-layout)
- [The pipeline](#the-pipeline)
- [Detection rules](#detection-rules)
- [The blockchain layer](#the-blockchain-layer)
- [Testing](#testing)
- [Design decisions](#design-decisions)
- [Known limitations](#known-limitations)

---

## What it does

Modern infrastructure produces logs in a dozen incompatible shapes. This
platform solves the resulting problem in four steps:

1. **Collect** — one agent per node reads every container's stdout off the
   node filesystem. Applications never talk to the platform directly.
2. **Normalize** — structured JSON and free-text access logs both land in
   Elastic Common Schema, so `source.ip` means the same thing everywhere.
3. **Enrich** — GeoIP, ASN, threat intelligence and user-agent classification
   are added at ingest, and secrets are redacted before anything is indexed.
4. **Detect** — 17 rules stored as JSON in git, installed into Kibana by
   script, and tested offline on every commit.

---

## Architecture

```
  ┌───────────────┐ ┌──────────┐ ┌──────────────┐   Workloads write ECS JSON
  │ chain-node    │ │  nginx   │ │ payments-api │   and a combined access log
  │ x3 validators │ │ (access) │ │  (ECS JSON)  │   to stdout. Nothing writes
  │ consensus/RPC │ │          │ │              │   to the platform directly.
  └───────┬───────┘ └────┬─────┘ └──────┬───────┘
          │ stdout       │ stdout       │ stdout
          └──────────────┼──────────────┘
                         ▼
            /var/log/containers/*.log          The container runtime writes
                         │                     stdout to the node filesystem
                         ▼
            ┌───────────────────────┐          One agent per node, not a
            │    Elastic Agent      │DaemonSet sidecar per pod. Adds Kubernetes
            │  (filestream input)   │          metadata; tracks read offsets.
            └───────────┬───────────┘
                        │ Beats protocol :5044
                        ▼
            ┌───────────────────────┐          PARSE     JSON / grok
            │      Logstash         │Deployment NORMALIZE ECS, severity, dedup
            │   5-stage pipeline    │(2 replicas) ENRICH  geoip, ASN, threat
            │   persistent queue    │          REDACT    secrets, PANs, JWTs
            └───────────┬───────────┘          ROUTE     by event.dataset
                        │ bulk, TLS
                        ▼
            ┌───────────────────────┐          3 nodes, quorum of 2.
            │    Elasticsearch      │StatefulSet Data streams per dataset,
            │  logs-* data streams  │(3 replicas) ILM: 90d security / 14d ops
            └───────────┬───────────┘
                        │
                        ▼
            ┌───────────────────────┐          3 dashboards, 17 detection
            │       Kibana          │          rules installed from git via
            │ dashboards + rules    │          the Detection Engine API
            └───────────────────────┘
```

**One property worth calling out:** the monitored workloads have *zero network
egress*. Their logs leave via stdout and are collected off the node filesystem,
so a compromised application has no network path to the logging platform. This
is enforced by NetworkPolicy, not convention.

---

## Quick start

### Full stack (Docker)

Requires Docker with ~6GB available, plus `jq` and Python 3.

```bash
cp .env.example .env          # change the passwords if this is not a laptop
make up                       # build and start everything (~3 min first run)
make bootstrap                # ILM policies, index templates, rules, dashboards
make demo                     # run every attack scenario, then baseline traffic
```

Kibana at <http://localhost:5601> (user `elastic`, password from `.env`):

- **Sentinel — Security Overview** — auth outcomes, attack signatures, sources
- **Sentinel — Operational Overview** — ingest volume, error rates, parser health
- **Sentinel — Blockchain Node Security** — slashing, RPC probes, reorgs
- **Security → Alerts** — the rules that fired during `make demo`

### Blockchain testnet (no Docker needed)

The chain half runs on Python alone:

```bash
make chain-up                            # 3 nodes, 6 validators, real signatures
make chain-status                        # head, peers, slashing evidence
make chain-demo                          # every blockchain attack scenario
make chain-verify                        # evaluate all 17 rules on the capture
```

### Kubernetes

```bash
make k8s-secrets              # namespace + credentials (TLS certs are separate)
make k8s-deploy               # kustomize apply, then wait for rollouts
make k8s-forward              # Kibana on localhost:5601
```

`make help` lists every target.

---

## Repository layout

| Path | What it is |
|---|---|
| `logstash/pipeline/` | The five pipeline stages — input, parse, normalize, enrich, output |
| `logstash/templates/` | Index mappings, index settings, ILM retention policies |
| `kibana/detections/` | 17 detection rules as versioned JSON with ATT&CK mappings |
| `kibana/dashboards/` | Saved objects, generated by script rather than hand-written |
| `k8s/` | Namespace, NetworkPolicies, ES StatefulSet, Logstash, Kibana, Agent DaemonSet |
| `demo-app/` | Flask service emitting ECS security events |
| `blockchain-node/` | Proof-of-stake node: signatures, consensus, JSON-RPC, P2P |
| `scripts/` | Bootstrap, rule installer, dashboard generator, attack scenarios |
| `tests/` | Crypto vectors, consistency checks, offline detection simulator |
| `docs/` | Architecture decisions, index tuning rationale, roadmap, research |

---

## The pipeline

Logstash concatenates every `*.conf` in `logstash/pipeline/` in alphabetical
order into one runtime pipeline. The numeric prefixes are the stage order.

**`10-input.conf`** — Beats input from the agents, a TCP input for local
development, and a heartbeat. The heartbeat is what makes `OPS-002` possible:
without a known-good signal every 30 seconds, a dead pipeline and a quiet night
look identical.

**`20-parse.conf`** — Two paths. Application logs arrive as ECS JSON and are
unwrapped into the event root, with collector-set fields protected from being
overwritten by anything the application claims about itself. nginx access logs
arrive as free text and are matched against a grok pattern with a 500ms timeout
so one pathological line cannot stall a worker. Anything matching neither path
is tagged and routed to a separate stream rather than dropped — a rising count
there means a log format changed upstream.

**`30-normalize.conf`** — Canonical `@timestamp` from the application's own
clock rather than receipt time, an `ingested_lag_sec` field that climbs long
before anything is lost, HTTP status classification, URL path/query split, a
normalized log-level vocabulary, a 0–100 severity score, and a content-derived
fingerprint used as the document `_id`.

That fingerprint makes the pipeline **idempotent**: if an agent replays a file
after a crash, or Logstash retries a bulk request that actually succeeded, the
duplicate overwrites itself instead of double-counting every dashboard.

**`40-enrich.conf`** — Private-range detection before GeoIP (so RFC1918
addresses don't waste a lookup), city/country and ASN enrichment, a threat
intelligence lookup that refreshes every 300s without a pipeline restart,
user-agent classification, and redaction of passwords, bearer tokens, JWTs and
card numbers.

Enrichment happens at ingest rather than query time. That costs CPU once per
event instead of on every dashboard refresh, and it freezes the answer as it
was at the time of the event — for geo and threat intel, that is the correct
semantic. You want to know what that IP was when it hit you.

**`90-output.conf`** — Routes by `event.dataset` into separate data streams so
retention, mappings and volume are managed per dataset.

---

## Detection rules

Rules live in `kibana/detections/detection-rules.json` and are installed by
`scripts/install-detections.sh`, which upserts by `rule_id` and is safe to run
from CI on every merge.

### Application & platform

| ID | Rule | Severity | ATT&CK |
|---|---|---|---|
| SEC-001 | Brute force — repeated failures against one account | high | T1110.001 |
| SEC-002 | Password spray — one password across many accounts | high | T1110.003 |
| SEC-003 | Endpoint enumeration — high 404 ratio from one source | medium | T1595.003 |
| SEC-004 | Web attack payload — injection or traversal matched | high | T1190 |
| SEC-005 | Possible data exfiltration — anomalous bulk reads | critical | T1530 |
| SEC-006 | Privilege escalation — admin role granted | high | T1098 |
| SEC-007 | Threat intelligence match | high | T1071 |
| OPS-001 | Error rate spike — sustained 5xx | medium | — |
| OPS-002 | Log pipeline stalled — no heartbeat | high | — |

### Blockchain node

| ID | Rule | Severity | Signal |
|---|---|---|---|
| BC-001 | RPC administrative namespace probe | critical | distinct `admin_*`/`personal_*` methods per source |
| BC-002 | RPC resource exhaustion | high | wide-range queries, request floods |
| BC-003 | Deep chain reorganisation | critical | `reorg_depth > 2` |
| BC-004 | Slashable offence | critical | conflicting signatures for one slot |
| BC-005 | Validator liveness degraded | high | missed duties, stalled finality |
| BC-006 | Mempool flooding | high | transaction spam per source |
| BC-007 | Invalid block propagation | high | rejections per peer |
| BC-008 | Peer table churn (eclipse) | high | connect/disconnect rate |

### Why rules as code

Rules built by clicking through the Kibana UI exist only in that cluster.
Keeping them as JSON in git means they are reviewable in a pull request,
diffable when a threshold changes, and reproducible when the cluster is rebuilt
— and tuning becomes a commit with a reason attached rather than an
undocumented change someone made at 2am.

Every rule carries documented false positives and investigation steps. **A rule
with no documented false positives has not been tuned**, and an alert with no
triage guidance is an alert that gets ignored — both are enforced by tests.

### Two design notes

**SEC-001 and SEC-002 are deliberately a pair.** Brute force is many attempts
against one account. Spraying is one password against many accounts, staying
under the per-account lockout threshold the whole time. A rule keyed on
`source.ip + user.name` catches the first and is *structurally blind* to the
second, which is why SEC-002 keys on cardinality of `user.name` instead.

**BC-004 has no threshold, and none is defensible.** A single double-signature
ejects a validator immediately and incurs a penalty that scales with how much
stake was slashed in the same window. Waiting for a second occurrence would be
waiting while the meter runs. That inverts the usual shape: in application
security the high-severity rules are thresholds, because one failed login means
nothing. Here they are single-occurrence queries.

---

## The blockchain layer

`blockchain-node/` is a miniature proof-of-stake chain that exists to be
monitored. It is the workload this platform watches, not a product in itself.

**Why it exists:** detections are only convincing if you can show them firing.
A real client cannot be made to double-sign on demand; a node you control can.

**Why this domain:** two documented gaps, researched from primary sources in
[`docs/blockchain-use-cases.md`](docs/blockchain-use-cases.md).

1. **The JSON-RPC surface is attacked constantly and is hard to see.** The
   Ethereum execution API spec defines no authentication for public namespaces.
   A six-month academic honeypot recorded 308 million RPC requests from 1,072
   distinct sources. The sharper half: Geth's own RPC log records request id,
   duration and error — *not the client's IP* — and logs below default
   verbosity, so detection has to come from a reverse proxy. That is exactly
   the access-log path this pipeline already parses.

2. **There is no common log schema.** Elastic Common Schema has 53 fieldsets
   and none are blockchain-related. A chain reorganisation is logged by Geth as
   `drop`, Lighthouse as `reorg_distance`, Prysm as `depth`, and Nimbus doesn't
   report depth at all. Normalizing that is precisely what ECS does for IT.

**What's modelled faithfully:** real secp256k1 ECDSA with RFC 6979
deterministic nonces, both slashing conditions, fork choice with reorg depth,
and the JSON-RPC namespace structure. What's simplified — SHA3 instead of
Keccak, HTTP instead of devp2p, in-memory anti-slashing — is listed with
reasoning in [`docs/blockchain-node.md`](docs/blockchain-node.md).

### Attack scenarios

```bash
make chain-attack SCENARIO=double_sign
```

| Scenario | Fires | What it stages |
|---|---|---|
| `rpc_namespace_probe` | BC-001 | Scans for exposed `admin`/`personal`/`debug` methods |
| `getlogs_exhaustion` | BC-002 | Caller-controlled query ranges |
| `rpc_flood` | BC-002 | High request volume from one source |
| `mempool_flood` | BC-006 | Transaction spam plus replays |
| `invalid_blocks` | BC-007 | Malformed and wrongly-signed blocks |
| `peer_churn` | BC-008 | Rapid peer cycling — the eclipse signature |
| `double_sign` | BC-004 | A second node with **overlapping validator keys** |
| `deep_reorg` | BC-003 | A competing branch that rewrites history |
| `validator_offline` | BC-005 | Stalls the node so it misses duties |

The `double_sign` scenario is the centrepiece, and it is not a contrived
attack. It reproduces the most common cause of real slashing: an operator fails
over to a standby without cleanly stopping the original, so the same keys are
live in two places. Both instances behave honestly. The pair of signatures is
still slashable — and two independent nodes derive **identical evidence
hashes**, because the offence is provable from signed messages alone.

---

## Testing

```bash
make test                                    # everything offline, no cluster
python3 tests/simulate_detections.py <log>   # replay a capture through the rules
```

**`tests/test_crypto.py`** — 29 checks verifying the secp256k1 implementation
against *published test vectors* and curve invariants, not just round-trips.
Hand-written curve code is exactly the kind of thing that is subtly wrong while
appearing to work: a broken implementation happily verifies its own signatures
while producing points that are not on the curve.

**`tests/test_platform_consistency.py`** — 165 checks across the pipeline,
mappings, templates and rules. These catch the class of bug that is invisible
in any single file and only surfaces as "the dashboard is empty" hours later:

- a rule querying a field the index template never maps (an unmapped field
  never matches, so the rule silently never fires)
- a rule pointing at a data stream nothing writes to
- a security dataset that doesn't match a security index pattern, so it falls
  through to the catch-all and is deleted after 14 days instead of 90
- a rule whose lookback window doesn't exceed its interval, leaving a gap
  between runs where events are never evaluated
- `risk_score` outside the band Kibana expects for its `severity`

The last three were **real bugs these tests found during development**, which
is the point of writing them.

**`tests/simulate_detections.py`** — reimplements the threshold and cardinality
semantics of the Detection Engine over a JSONL file, so a rule change can be
verified in seconds without standing up Elasticsearch. It respects each rule's
`index` list; without that it over-reports badly, counting auth failures toward
an error-rate rule that only looks at access logs.

CI runs all of it plus a live testnet on every push.

---

## Design decisions

Fuller write-ups in [`docs/architecture.md`](docs/architecture.md) and
[`docs/index-settings-rationale.md`](docs/index-settings-rationale.md).

**`dynamic: false` on the index mappings.** The single most important setting
in the template. Logs contain attacker-controlled keys; with dynamic mapping
on, one request carrying 5,000 unique JSON keys creates 5,000 fields and
cluster state grows until the master node falls over.

**Three Elasticsearch nodes, not two.** Quorum is `(n/2)+1`. With two nodes the
quorum is two, so losing either makes the cluster unavailable — strictly worse
than a single node. Three is the smallest count that tolerates one failure.

**A DaemonSet, not a sidecar per pod.** A sidecar doubles the pod count,
duplicates the agent's memory across every replica, and makes a collector
upgrade a redeploy of every application.

**Persistent queue, not the in-memory default.** With the memory queue a pod
eviction silently loses whatever was in flight. For security logs that is a gap
in the audit trail precisely when something is going wrong.

**A liveness probe on the TCP transport port, not HTTP health.** An
Elasticsearch node under heavy GC can fail an HTTP probe while being perfectly
recoverable; restarting it makes things worse.

**Tiered retention.** Security datasets 90 days, operational 14, unparsed 3.
Access logs are the bulk of the byte volume and the least valuable per byte;
one retention policy would force the longest on everything.

---

## Known limitations

Stated rather than left to be discovered. Full list with reasoning in
[`docs/roadmap.md`](docs/roadmap.md).

- **Logstash's persistent queue is on an `emptyDir`**, so it does not survive a
  pod restart. The correct fix is a StatefulSet with a PVC; it is an `emptyDir`
  so the manifests deploy on a cluster with no dynamic provisioner.
- **The node detects double-signing but does not prevent it.** A real validator
  client keeps its signing history in a persistent anti-slashing database so a
  restart cannot forget a past signature. This one keeps it in memory.
- **SEC-005 counts bulk-read events rather than summing record counts**,
  because Kibana threshold rules cannot aggregate a numeric field.
- **OPS-002 cannot be expressed as a query.** Absence-of-signal needs the alert
  condition inverted in the UI, or an Elasticsearch Watcher.
- **The chain uses SHA3-256, not Keccak-256**, so addresses are not
  Ethereum-compatible. Deliberate: it is a monitored workload, not a wallet.
- **P2P is HTTP, not devp2p.** The monitored events have the same shape
  regardless of transport, but anything depending on peer discovery is out of
  reach.
- **TLS certificates are not generated.** `make k8s-secrets` creates the
  credentials; the `elasticsearch-certs` secret must come from cert-manager or
  `elasticsearch-certutil`.

---

## Tech stack

**Platform** — Elasticsearch 8.13, Logstash, Kibana, Elastic Agent, Filebeat
**Orchestration** — Kubernetes (StatefulSet, Deployment, DaemonSet, NetworkPolicy, RBAC), Kustomize, Docker Compose
**Languages** — Python 3.12 (Flask, gunicorn), Logstash DSL, Bash
**Standards** — Elastic Common Schema, MITRE ATT&CK, JSON-RPC 2.0
**CI** — GitHub Actions
