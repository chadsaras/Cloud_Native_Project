#!/usr/bin/env python3
"""Consistency tests across the pipeline, mappings and detection rules.

These catch the specific class of bug that is invisible in any single file and
only shows up as "the dashboard is empty" hours later:

  - a detection rule querying a field the index template never maps
  - a detection rule pointing at a data stream the pipeline never writes to
  - the app emitting an event.dataset that no index template matches, so it
    silently lands on the catch-all with the wrong retention

They need no cluster and no Docker, so they run in CI on every commit.

Run:  python3 tests/test_platform_consistency.py
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

failures: list[str] = []
passes: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        passes.append(name)
    else:
        failures.append(f"{name}: {detail}")


def load(path: str):
    with open(os.path.join(ROOT, path)) as fh:
        return json.load(fh)


def read(path: str) -> str:
    with open(os.path.join(ROOT, path)) as fh:
        return fh.read()


# --- Collect the mapped field names from the component template --------------

def flatten_mapping(props: dict, prefix: str = "") -> set:
    """Turn nested ES mapping properties into dotted field names."""
    out = set()
    for key, val in props.items():
        full = f"{prefix}{key}"
        out.add(full)
        if isinstance(val, dict) and "properties" in val:
            out |= flatten_mapping(val["properties"], f"{full}.")
    return out


mappings = load("logstash/templates/component-logs-mappings.json")
MAPPED = flatten_mapping(mappings["template"]["mappings"]["properties"])

rules_doc = load("kibana/detections/detection-rules.json")
RULES = rules_doc["rules"]

pipeline_src = "\n".join(
    read(f"logstash/pipeline/{f}")
    for f in sorted(os.listdir(os.path.join(ROOT, "logstash", "pipeline")))
)
app_src = (read("demo-app/app/security_events.py") + read("demo-app/app/main.py")
           + read("blockchain-node/node/events.py") + read("blockchain-node/node/main.py")
           + read("blockchain-node/node/rpc.py"))


# --- 1. Every field a detection rule queries must be mapped ------------------

FIELD_RE = re.compile(r"\b([a-z_]+(?:\.[a-z_]+)+)\s*:")

for rule in RULES:
    queried = set(FIELD_RE.findall(rule["query"]))
    for tf in rule.get("threshold", {}).get("field", []):
        queried.add(tf)
    for card in rule.get("threshold", {}).get("cardinality", []):
        queried.add(card["field"])

    for field in sorted(queried):
        # labels.* is the one intentionally dynamic subtree.
        if field.startswith("labels."):
            continue
        check(
            f"[{rule['rule_id']}] field '{field}' is mapped",
            field in MAPPED,
            f"'{field}' is queried by the rule but absent from the index "
            f"template. An unmapped field never matches, so the rule would "
            f"silently never fire.",
        )


# --- 2. Every index pattern a rule targets must be produced somewhere --------
# Datasets come from event.dataset, set either by the app or by the pipeline.

app_datasets = set(re.findall(r'"dataset":\s*"([a-z0-9._]+)"', app_src))
pipe_datasets = set(re.findall(r'"\[event\]\[dataset\]"\s*=>\s*"([a-z0-9._]+)"', pipeline_src))
pipe_streams = set(re.findall(r'data_stream_dataset\s*=>\s*"([a-z0-9._]+)"', pipeline_src))
PRODUCED = app_datasets | pipe_datasets | pipe_streams

for rule in RULES:
    for pattern in rule["index"]:
        # logs-* / metrics-* wildcards match anything by construction.
        if pattern in ("logs-*", "metrics-*"):
            continue
        stem = pattern.replace("logs-", "").replace("metrics-", "").rstrip("-*")
        matched = any(ds == stem or ds.startswith(stem.rstrip("*")) for ds in PRODUCED)
        check(
            f"[{rule['rule_id']}] index '{pattern}' has a producer",
            matched,
            f"no component emits event.dataset matching '{stem}'. "
            f"Produced datasets: {sorted(PRODUCED)}",
        )


# --- 3. Every produced dataset must match an index template pattern ----------
# Otherwise it lands on the catch-all with operational (14d) retention, which
# for a security dataset is a silent retention downgrade.

bootstrap = read("scripts/bootstrap-elasticsearch.sh")
tpl_patterns = re.findall(r'"index_patterns":\s*\[([^\]]+)\]', bootstrap)
ALL_PATTERNS = []
for group in tpl_patterns:
    ALL_PATTERNS += re.findall(r'"([^"]+)"', group)

SECURITY_PATTERNS = [p for p in ALL_PATTERNS
                     if any(k in p for k in ("auth", "iam", "waf", "data",
                                             "consensus", "rpc", "p2p"))]

for ds in sorted(app_datasets):
    full = f"logs-{ds}-default"
    matched = [p for p in ALL_PATTERNS if re.fullmatch(p.replace(".", r"\.").replace("*", ".*"), full)]
    check(
        f"dataset '{ds}' matches an index template",
        bool(matched),
        f"'{full}' matches no index_patterns in bootstrap-elasticsearch.sh",
    )

# Security datasets specifically must hit a security template, not the catch-all.
SECURITY_SUFFIXES = ("auth", "iam", "waf", "data", "consensus", "rpc", "p2p")
for ds in sorted(d for d in app_datasets if d.split(".")[-1] in SECURITY_SUFFIXES):
    full = f"logs-{ds}-default"
    hit = [p for p in SECURITY_PATTERNS
           if re.fullmatch(p.replace(".", r"\.").replace("*", ".*"), full)]
    check(
        f"security dataset '{ds}' gets 90d retention",
        bool(hit),
        f"'{full}' does not match a security index pattern, so it would fall "
        f"through to the catch-all and be deleted after 14 days instead of 90.",
    )


# --- 4. ILM policies referenced by templates must exist ----------------------

ilm = load("logstash/templates/ilm-policies.json")
referenced = set(re.findall(r'"index\.lifecycle\.name":\s*"([a-z0-9.-]+)"', bootstrap))
for policy in sorted(referenced):
    check(
        f"ILM policy '{policy}' is defined",
        policy in ilm,
        f"template references '{policy}' but it is not in ilm-policies.json. "
        f"Defined: {sorted(ilm)}",
    )


# --- 5. Rule internal sanity -------------------------------------------------

def to_seconds(spec: str) -> int:
    m = re.fullmatch(r"(?:now-)?(\d+)([smhd])", spec)
    if not m:
        return 0
    n, unit = int(m.group(1)), m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


for rule in RULES:
    interval = to_seconds(rule["interval"])
    lookback = to_seconds(rule["from"])
    check(
        f"[{rule['rule_id']}] lookback exceeds interval",
        lookback > interval,
        f"from={rule['from']} ({lookback}s) is not greater than "
        f"interval={rule['interval']} ({interval}s). Without overlap, events "
        f"arriving during the indexing delay fall between two runs and are "
        f"never evaluated.",
    )
    check(
        f"[{rule['rule_id']}] has MITRE mapping or is an OPS rule",
        bool(rule.get("threat")) or rule["rule_id"].startswith("OPS"),
        "security rules should carry an ATT&CK mapping",
    )
    check(
        f"[{rule['rule_id']}] documents false positives",
        bool(rule.get("false_positives")),
        "a rule with no documented false positives has not been tuned",
    )
    check(
        f"[{rule['rule_id']}] has investigation steps",
        bool(rule.get("investigation_steps")),
        "an alert with no triage guidance is an alert that gets ignored",
    )
    sev, score = rule["severity"], rule["risk_score"]
    bands = {"low": (0, 21), "medium": (21, 47), "high": (47, 79), "critical": (79, 101)}
    lo, hi = bands[sev]
    check(
        f"[{rule['rule_id']}] risk_score {score} matches severity '{sev}'",
        lo <= score < hi,
        f"Kibana expects risk_score in [{lo},{hi}) for severity '{sev}'",
    )


# --- 6. The app must not log anything that looks like a live secret ----------

for pattern, label in [
    (r'password\s*=\s*["\'](?!demo-)[^"\']{8,}', "hardcoded non-demo password"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key"),
    (r'-----BEGIN [A-Z ]*PRIVATE KEY-----', "private key"),
]:
    hits = re.findall(pattern, app_src)
    check(f"no {label} in application source", not hits, f"found: {hits[:2]}")


# --- Report ------------------------------------------------------------------

print(f"\n{'=' * 72}")
print(f"  {len(passes)} passed, {len(failures)} failed")
print("=" * 72)

if failures:
    print("\nFAILURES:\n")
    for f in failures:
        print(f"  x {f}\n")
    sys.exit(1)

print("\nAll consistency checks passed.\n")
print("Checked:")
print(f"  - {len(RULES)} detection rules against {len(MAPPED)} mapped fields")
print(f"  - {len(PRODUCED)} produced datasets against {len(ALL_PATTERNS)} index patterns")
print(f"  - {len(ilm)} ILM policies\n")
sys.exit(0)
