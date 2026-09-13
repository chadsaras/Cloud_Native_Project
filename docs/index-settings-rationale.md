# Why the index settings are what they are

Each of these was a deliberate choice with a cost on the other side. Written
down because "why is refresh_interval 10s" is exactly the question that gets
asked six months later when nobody remembers.

### `refresh_interval: 10s` (default is 1s)

A refresh is what makes newly indexed documents visible to search, and it
creates a new Lucene segment every time. At 1s the cluster spends a large
fraction of its IO budget creating and then merging tiny segments.

For logs, 10s is the right trade: nobody is making a decision based on whether
a log line appeared one second or ten seconds ago, and the indexing throughput
gain is substantial (roughly 15-25% in the load test in `tests/`).

The cost: a detection rule that runs every 30s could miss an event that was
indexed but not yet refreshed. This is why the detection rules in
`kibana/detections/` all use a lookback window larger than their interval.

### `codec: best_compression` (default is `LZ4`)

DEFLATE instead of LZ4 for stored fields. Roughly 20-30% smaller on disk for
log data, which compresses well because of how repetitive it is.

The cost is CPU on read - fetching `_source` for a document is slower. That is
acceptable because the dominant query pattern here is aggregation over indexed
fields (which does not touch `_source`), and the retrieval that does happen is
a few hundred documents in a Discover pane, not millions.

### `sort.field: @timestamp desc`

Index sorting physically orders documents within each segment by timestamp
descending. Every dashboard query and every Discover view here is
"most recent first, within a time range", and index sorting lets Lucene stop
early instead of scanning the full segment.

The cost is paid at index time (documents must be sorted before being written)
and it is the reason `refresh_interval` matters even more here.

### `number_of_shards: 1`

A shard should hold 10-50GB. At this platform's volume a daily data stream
backing index is well under that, so one shard is correct. More shards would
mean more overhead per query with no parallelism gain.

This is the setting most often got wrong by over-provisioning: a cluster with
thousands of tiny shards spends all its time on cluster-state bookkeeping.
ILM rollover (see `ilm-policies.json`) is the mechanism that keeps shard size
in the right band as volume grows, not a large static shard count.

### `mapping.total_fields.limit: 2000`

A guardrail, not a target. Combined with `dynamic: false` in the mappings
component it means a field explosion is impossible: unknown fields are not
mapped at all, and even if `labels.*` (the one dynamic area) is abused, the
limit stops the cluster state from growing without bound.

### `mapping.ignore_malformed: true`

If a document arrives with a string where the mapping says `ip`, index the rest
of the document and flag that one field rather than rejecting the whole event.

For security logs, a partially-indexed event is far more useful than a rejected
one - the rejected event is a hole in the audit trail. The malformed field is
still in `_source` and the document carries `_ignored`, so these are findable
with `_exists_:_ignored`.
