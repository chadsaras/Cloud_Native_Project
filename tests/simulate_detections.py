#!/usr/bin/env python3
"""Evaluate the detection rules against a captured log file, offline.

This is the rules' unit test. It reimplements the threshold and cardinality
semantics of the Kibana Detection Engine over a JSONL file so a rule change can
be verified in seconds without standing up Elasticsearch, and so CI can prove
that every rule still fires on its own scenario.

The reimplementation is deliberately small and covers only the rule types this
project uses (`query` and `threshold`). It is a test harness, not a second
detection engine.

Usage:
    python3 tests/simulate_detections.py <app-log.jsonl>
"""

import json
import os
import re
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = json.load(open(os.path.join(ROOT, "kibana/detections/detection-rules.json")))["rules"]

# Which scenario in traffic_generator.py is supposed to trigger each rule.
EXPECTED = {
    "SEC-001": "brute_force",
    "SEC-002": "password_spray",
    "SEC-003": "enumeration",           # needs nginx logs; see note below
    "SEC-004": "web_attack",
    "SEC-005": "data_exfil",
    "SEC-006": "privilege_escalation",
    "SEC-007": "any (threat intel enrichment happens in Logstash)",
    "OPS-001": "baseline error rate",
    "OPS-002": "absence of heartbeat",
}

# Rules that cannot be evaluated against the application log alone.
NOT_APPLICABLE = {
    "SEC-003": "queries logs-nginx.access-*; nginx runs only in the Docker stack",
    "SEC-007": "matches threat.indicator.*, which Logstash adds during enrichment",
    "OPS-002": "absence-of-signal over the Logstash heartbeat stream",
}


def get(doc: dict, dotted: str):
    """Read a dotted ECS path out of a nested document."""
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def matches(doc: dict, query: str) -> bool:
    """Evaluate the KQL subset the rules actually use: `and`, `or`, `not`,
    `field:value` and `field:*`."""
    # Rules here use `and` at the top level, plus one `or` in OPS-001.
    for clause in re.split(r"\s+or\s+", query):
        if all(_term(doc, t) for t in re.split(r"\s+and\s+", clause.strip())):
            return True
    return False


# KQL range terms: `field > 2`, `field >= 2`, and so on. BC-003 depends on
# one of these (`blockchain.reorg_depth > 2`), and without handling them the
# comparison is silently treated as an always-true term, which turns a
# depth-thresholded rule into one that fires on every reorg.
RANGE_RE = re.compile(r"^([a-z_][\w.]*)\s*(>=|<=|>|<)\s*(-?\d+(?:\.\d+)?)$", re.I)


def _term(doc: dict, term: str) -> bool:
    term = term.strip().strip("()")
    negate = False
    if term.startswith("not "):
        negate, term = True, term[4:].strip()

    range_match = RANGE_RE.match(term)
    if range_match:
        field, operator, literal = range_match.groups()
        have = get(doc, field)
        if have is None or isinstance(have, (dict, list)):
            return negate
        try:
            left, right = float(have), float(literal)
        except (TypeError, ValueError):
            return negate
        result = {">": left > right, ">=": left >= right,
                  "<": left < right, "<=": left <= right}[operator]
        return not result if negate else result

    if ":" not in term:
        return True
    field, _, want = term.partition(":")
    have = get(doc, field.strip())
    want = want.strip().strip('"')

    if want == "*":
        result = have is not None
    elif isinstance(have, list):
        result = want in [str(x) for x in have]
    else:
        result = str(have) == want
    return not result if negate else result


def in_scope(doc: dict, patterns: list) -> bool:
    """Does this event live in one of the data streams the rule targets?

    Without this the simulator over-reports: OPS-001 queries
    `event.outcome:failure` but only over logs-nginx.access-* and
    logs-app.checkout-*, so an auth failure must not count toward it even
    though it matches the query text. Ignoring the index list is the
    difference between a harness that validates a rule and one that just
    greps.
    """
    dataset = get(doc, "event.dataset")
    if dataset is None:
        return False
    for pattern in patterns:
        stem = pattern.replace("logs-", "").replace("metrics-", "")
        stem = stem[:-len("-*")] if stem.endswith("-*") else stem
        if stem in ("*", ""):
            return True
        regex = re.escape(stem).replace(r"\*", ".*")
        if re.fullmatch(regex, dataset):
            return True
    return False


class NoSignal(Exception):
    """The capture contains nothing this rule could possibly match.

    Distinct from "did not fire". A blockchain-only capture has no auth events,
    so SEC-001 not firing says nothing about SEC-001 -- treating that as a
    failure would make every partial capture look like a regression and train
    whoever runs this to ignore the result.
    """


def evaluate(rule: dict, docs: list) -> tuple[bool, str]:
    scoped = [d for d in docs if in_scope(d, rule["index"])]
    if not scoped:
        raise NoSignal(f"no events in {', '.join(rule['index'])}")

    hits = [d for d in scoped if matches(d, rule["query"])]
    if not hits:
        return False, f"0 of {len(scoped)} in-scope events matched the query"

    if rule["type"] == "query":
        return True, f"{len(hits)} matching events (fires on any match)"

    th = rule["threshold"]
    fields = th["field"]
    cards = th.get("cardinality", [])

    groups = defaultdict(list)
    for d in hits:
        key = tuple(str(get(d, f)) for f in fields)
        groups[key].append(d)

    for key, group in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        if len(group) < th["value"]:
            continue
        if cards:
            card = cards[0]
            distinct = {str(get(d, card["field"])) for d in group}
            if len(distinct) < card["value"]:
                continue
            return True, (f"{'/'.join(key)}: {len(group)} events, "
                          f"{len(distinct)} distinct {card['field']} "
                          f"(needs {th['value']}/{card['value']})")
        return True, f"{'/'.join(key)}: {len(group)} events (needs {th['value']})"

    biggest = max((len(g) for g in groups.values()), default=0)
    return False, f"{len(hits)} events but largest group is {biggest}, under threshold {th['value']}"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__); return 2
    path = sys.argv[1]
    docs = []
    for line in open(path):
        line = line.strip()
        if line.startswith("{"):
            try:
                docs.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    print(f"\nEvaluating {len(RULES)} rules against {len(docs)} events from {os.path.basename(path)}\n")
    print(f"  {'RULE':9} {'RESULT':10} DETAIL")
    print(f"  {'-'*9} {'-'*10} {'-'*56}")

    fired = skipped = missed = 0
    for rule in RULES:
        rid = rule["rule_id"]
        if rid in NOT_APPLICABLE:
            print(f"  {rid:9} {'n/a':10} {NOT_APPLICABLE[rid]}")
            skipped += 1
            continue
        try:
            ok, detail = evaluate(rule, docs)
        except NoSignal as exc:
            print(f"  {rid:9} {'n/a':10} {exc}")
            skipped += 1
            continue
        if ok:
            print(f"  {rid:9} {'FIRED':10} {detail}")
            fired += 1
        else:
            print(f"  {rid:9} {'no alert':10} {detail}")
            missed += 1

    print(f"\n  {fired} fired, {missed} did not fire, "
          f"{skipped} not applicable to this capture\n")

    # Every applicable rule has a scenario that is supposed to trigger it. If
    # one of them did not fire after `--scenario all`, either the rule is
    # broken or the scenario is - both are failures worth catching in CI.
    if missed:
        print("  A rule listed as 'no alert' HAD in-scope events and still did not")
        print("  fire. After `--scenario all` against the matching workload, that")
        print("  is a regression: either the rule or its scenario is broken.\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
