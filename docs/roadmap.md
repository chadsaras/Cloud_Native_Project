# Known limitations and what would come next

Written down rather than left implicit. Every item here is a real constraint in
the current implementation, with the reason it was accepted and what the fix
looks like.

---

## 1. Logstash's persistent queue does not survive a pod restart

**Now:** `k8s/logstash/deployment.yaml` mounts `/usr/share/logstash/data` as an
`emptyDir`. The queue is configured as `persisted` and works correctly within
the pod's lifetime, but the volume is deleted when the pod is.

**Why it is like this:** an `emptyDir` deploys on any cluster. A PVC requires a
dynamic provisioner, which not every evaluation cluster (kind, minikube without
addons) has.

**Fix:** convert the Deployment to a StatefulSet with a `volumeClaimTemplate`.
This also means losing `maxUnavailable: 0` rolling behaviour, since StatefulSet
updates are ordinal — so the trade is durability against rollout speed.

---

## 2. SEC-005 counts events instead of summing records

**Now:** the rule fires on four or more `bulk_read` events from one user. At the
5000-record maximum page size that is 20000 records, but a user making many
small reads totalling far more would not trigger it.

**Why it is like this:** Kibana threshold rules cannot aggregate a numeric
field. They count documents and optionally count distinct values of a field.
`labels.record_count` is mapped and present on every event; there is simply no
threshold rule type that sums it.

**Fix:** an ES|QL rule (`STATS total = SUM(labels.record_count) BY user.name`),
available in the Detection Engine from 8.11. Worth doing; it was left out here
because ES|QL rule syntax is still changing between minor versions and pinning
to it would date the project faster than the threshold version.

---

## 3. OPS-002 cannot be expressed as a query

**Now:** the rule is defined and installed, but alerting on the *absence* of
heartbeats requires the alert condition to be inverted in the Kibana UI. The
installer script says so explicitly rather than failing silently.

**Why it is like this:** a query returns what matched. "Nothing matched" is not
something a query can express as a hit.

**Fix:** an Elasticsearch Watcher with a `compare` condition on
`ctx.payload.hits.total == 0`, or the Kibana "no results" rule type. The
Watcher version is more portable and does not depend on Kibana being up — which
matters, because Kibana being down is one of the reasons the heartbeat might
stop arriving.

---

## 4. The threat intelligence feed is a static file

**Now:** `logstash/config/threat_intel.yml`, refreshed by the `translate` filter
every 300 seconds. Indicators are RFC 5737 documentation addresses so nothing
in the repository points at a real host.

**Why it is like this:** the demo has to be reproducible offline, and a live
feed makes test results depend on what a third party published that morning.

**Fix:** point the same filter at a file rendered from MISP or a commercial
feed by a CronJob, or switch to the Elasticsearch `enrich` processor against a
threat index. The pipeline change is a few lines — the mechanism is identical.
The real work is indicator lifecycle: expiry, confidence scoring, and a source
attribution field, since `SEC-007`'s documented false positive is precisely a
stale indicator whose IP has been reassigned.

---

## 5. No TLS certificate generation

**Now:** `make k8s-secrets` creates the credential secrets. The
`elasticsearch-certs` secret (`tls.crt`, `tls.key`, `ca.crt`) must be created
separately.

**Why it is like this:** certificate lifecycle belongs to the cluster's PKI, not
to an application repository. Generating self-signed certificates in a Makefile
teaches the wrong habit.

**Fix:** a cert-manager `Certificate` resource with an internal issuer, which
also handles rotation. `elasticsearch-certutil` is the manual alternative.

---

## 6. No alert routing

**Now:** detection rules create alerts in Kibana. Nothing pages anyone.

**Fix:** Kibana connectors to PagerDuty or Slack, routed by severity — critical
pages, high goes to a queue, medium is dashboard-only. This is deliberately not
"send every alert to Slack": SEC-003 is documented as medium precisely because
scanning is constant background noise, and routing it anywhere with a
notification sound is the fastest way to train people to ignore the channel.

---

## 7. Detection coverage is narrow by design

Nine rules covering credential attacks, web exploitation, privilege escalation,
exfiltration and pipeline health. Obvious gaps, roughly in priority order:

- **Impossible travel** — successful logins from geographically distant
  locations within an implausible interval. The geo enrichment needed for it
  already exists, but it needs a stateful comparison against the previous
  login, which means an ES|QL or EQL sequence rule rather than a threshold.
- **First-seen anomalies** — a user authenticating from a new ASN, a service
  account calling an endpoint it has never called. Needs a baseline period.
- **EQL sequence rules** — "failed logins followed by a success from the same
  IP" is a much stronger signal than either half alone, and is exactly what
  SEC-001's investigation steps currently ask an analyst to check by hand.

---

## 8. Capacity has not been load tested at scale

The `refresh_interval` claim in `index-settings-rationale.md` (15–25% indexing
throughput gain) comes from a small local benchmark, not from a
production-scale test. Shard sizing guidance in this repository follows Elastic's
published 10–50GB recommendation rather than measurement on this workload.

**Fix:** a sustained load test with `esrally` against a representative cluster,
measuring indexing throughput, queue depth under backpressure, and the actual
point at which `max_primary_shard_size: 30gb` triggers rollover in practice.
