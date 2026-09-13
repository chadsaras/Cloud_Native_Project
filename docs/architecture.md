# Architecture decisions

The reasoning behind choices that are not obvious from the manifests. Each one
has a real cost on the other side; that cost is stated.

---

## Why Logstash at all, rather than agent → Elasticsearch directly

Elastic Agent can write straight to Elasticsearch, and for a simple collection
use case it should. Logstash is here because this platform does three things
that belong in a central processing tier:

1. **Enrichment that needs shared state** — the threat-intelligence lookup and
   the GeoIP/ASN databases. Putting those on every node's agent means
   distributing and refreshing the databases everywhere.
2. **Redaction before storage** — secrets must be stripped before they reach
   an index that is retained for 90 days and read by a wide audience. Doing it
   at the collector means trusting every collector; doing it centrally means
   one place to audit.
3. **A persistent queue that decouples producers from Elasticsearch** — when
   the cluster is unavailable, agents keep reading and Logstash absorbs the
   backlog. Without it, backpressure reaches the application nodes.

The cost is a whole additional tier to run, scale and monitor, plus added
latency. An ingest-pipeline-only design (agent → Elasticsearch, processing in
an ingest node pipeline) is a legitimate alternative and is simpler; it trades
away the queue and makes redaction logic harder to test.

---

## Why data streams rather than one large index

Routing by `event.dataset` into separate data streams buys three things:

- **Per-dataset retention.** Security events are kept 90 days; nginx access
  logs, which are the bulk of the byte volume and the least valuable per byte,
  are kept 14. One index would force the longest retention on everything.
- **Per-dataset mappings.** A field explosion in one dataset does not affect
  another.
- **Independent disposal.** A noisy dataset can be dropped without touching
  anything else.

The cost is more indices and therefore more shards to manage, which is why
`number_of_shards: 1` plus ILM rollover matters — see
[`index-settings-rationale.md`](index-settings-rationale.md).

---

## Why ECS, and why the application emits it directly

Elastic Common Schema means `source.ip` means the same thing whether the event
came from nginx, the application, or a future service written in another
language. Without it, every dashboard panel and every detection rule has to
know which field name each source happens to use, and adding a service means
editing all of them.

The application emits ECS JSON directly rather than writing plain text that
Logstash reconstructs. Parsing a line you already control is wasted work, and
grok against free-form text is the single most common source of pipeline
breakage when a log format drifts.

The unparsed-text path still exists deliberately: nginx writes a classic
combined access log that Logstash *does* grok. A real estate always has both,
so the pipeline handles both.

---

## Why enrichment happens at ingest, not query time

Ingest-time enrichment costs CPU once per event. Query-time enrichment costs it
on every dashboard refresh, for every viewer.

More importantly, it freezes the answer as it was at the time of the event. For
geolocation and threat intelligence that is the correct semantic: during an
investigation you want to know what that IP was when it hit you, not what it
resolves to today. An IP that was a known scanner in March and is a residential
address today should still read as a scanner on the March events.

The cost is that a correction to the threat feed does not retroactively fix old
events. That is the right trade for evidence, and the wrong one for, say, a
product catalogue.

---

## Why the document `_id` is a content fingerprint

`30-normalize.conf` computes a SHA-256 over timestamp, message, hostname and
service name, and `90-output.conf` uses it as the document `_id` with
`action: create`.

This makes the entire pipeline idempotent. Three things routinely cause the
same event to be delivered twice:

- an agent restarting and replaying from a stale offset
- Logstash retrying a bulk request that actually succeeded but whose
  acknowledgement was lost
- a manual replay of a captured file during an investigation

Without a stable id, each of those double-counts every metric on every
dashboard. With one, the duplicate overwrites itself.

The cost is a hash per event, and the risk that two genuinely distinct events
with identical content in the same millisecond collapse into one. For log data
that is an acceptable trade; for financial transactions it would not be.

---

## Why `event.severity` is a 0–100 number

Different sources express severity differently: syslog uses 0–7 descending,
application loggers use level names, the WAF has its own scale. A single
numeric field means one "top alerts" panel can rank events from completely
different detections against each other.

A threat-intelligence hit floors severity at 80 regardless of the log level
that carried it. An INFO-level line from a known-bad IP is not an INFO event.

---

## Why the collector runs as a DaemonSet with a narrow ClusterRole

One agent per node reads every container's logs from `/var/log/containers`.
The alternative — a sidecar in every application pod — doubles the pod count,
duplicates the agent's memory footprint across every replica of every service,
and turns a collector upgrade into a redeploy of every application.

The ClusterRole is read-only and covers only what is needed to turn a log file
path into meaningful metadata: which pod, which namespace, which labels. There
is no `create`, `update`, `patch` or `delete` anywhere in it. A collector runs
on every node in the cluster; one that can modify cluster state is a lateral
movement path, and it never needs to be.

The agent does run as root, because reading other containers' log files
requires it. That is narrowed by dropping every capability except
`DAC_READ_SEARCH`, which is the specific one that grants it.

---

## Why the read-offset registry is a `hostPath`

`/var/lib/elastic-agent-state` is mounted from the node, not an `emptyDir`.

With an `emptyDir`, every agent restart re-reads every log file from the
beginning. At any real volume that means the cluster is flooded with duplicates
of everything still on disk, immediately after the event that caused the
restart — which is usually the worst possible moment.

---

## Why the application has zero network egress

The NetworkPolicy on `payments-api` grants no egress at all. The application
does not need it: its logs leave via stdout and are collected off the node
filesystem by the agent.

This is a real security property of the architecture rather than a
configuration detail. A compromised application pod has no network path to the
logging platform, and therefore cannot tamper with, flood, or read the log
estate — even though its own events are flowing into it continuously.

---

## Why security is on in the local stack

The Docker Compose stack runs with `xpack.security.enabled=true` and a
bootstrap step that sets the `kibana_system` password, rather than disabling
security for convenience.

Elasticsearch creates the `elastic` superuser from `ELASTIC_PASSWORD` but
leaves the built-in `kibana_system` account without a usable password. Kibana
authenticates as that account, not as `elastic`. Without the bootstrap step,
Kibana fails authentication on every boot with a 401 that looks like a
configuration error and is routinely "fixed" by turning security off entirely —
which then becomes the pattern that gets copied to a real deployment.

TLS is off in Compose and on in Kubernetes. That difference is deliberate and
documented rather than silent: the moment the local stack is reachable from
anything but localhost it needs the certificate setup the manifests use.
