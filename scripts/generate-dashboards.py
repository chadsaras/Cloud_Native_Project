#!/usr/bin/env python3
"""Generate the Kibana saved-objects NDJSON.

Generated rather than hand-authored because Kibana saved objects embed their
state as a JSON *string* inside a JSON object. Hand-editing that means
escaping quotes by hand, and one mistake makes the whole import fail with an
error that does not say which object was wrong.

Run:  python3 scripts/generate-dashboards.py
Then: ./scripts/import-dashboards.sh
"""

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "kibana/dashboards/sentinel-dashboards.ndjson")

objects = []

DATA_VIEWS = [
    ("sentinel-logs-all", "logs-*", "All logs"),
    ("sentinel-logs-security",
     "logs-app.auth-*,logs-app.iam-*,logs-app.waf-*,logs-app.data-*", "Security events"),
    ("sentinel-logs-access", "logs-nginx.access-*", "HTTP access logs"),
    ("sentinel-logs-chain",
     "logs-blockchain.consensus-*,logs-blockchain.rpc-*,logs-blockchain.p2p-*,logs-blockchain.mempool-*",
     "Blockchain node events"),
]
for dv_id, pattern, title in DATA_VIEWS:
    objects.append({
        "id": dv_id, "type": "index-pattern",
        "attributes": {"title": pattern, "name": title, "timeFieldName": "@timestamp"},
        "references": [], "managed": False,
    })


def _layer_ref(layer="layer1"):
    return f"indexpattern-datasource-layer-{layer}"


def metric(obj_id, title, dv, query, color="#6092C0"):
    layer = "layer1"
    state = {
        "visualization": {"layerId": layer, "layerType": "data",
                          "metricAccessor": "col1", "color": color},
        "query": {"query": query, "language": "kuery"}, "filters": [],
        "datasourceStates": {"formBased": {"layers": {layer: {
            "columns": {"col1": {"label": title, "dataType": "number",
                                 "operationType": "count", "isBucketed": False,
                                 "sourceField": "___records___", "params": {}}},
            "columnOrder": ["col1"], "incompleteColumns": {}}}}},
    }
    return {"id": obj_id, "type": "lens",
            "attributes": {"title": title, "visualizationType": "lnsMetric", "state": state},
            "references": [{"type": "index-pattern", "id": dv, "name": _layer_ref()}],
            "managed": False}


def terms_bar(obj_id, title, dv, field, query, size=10):
    layer = "layer1"
    state = {
        "visualization": {"shape": "horizontal_bar", "preferredSeriesType": "bar_horizontal",
                          "legend": {"isVisible": False, "position": "right"},
                          "valueLabels": "inside",
                          "layers": [{"layerId": layer, "layerType": "data",
                                      "seriesType": "bar_horizontal",
                                      "xAccessor": "col1", "accessors": ["col2"]}]},
        "query": {"query": query, "language": "kuery"}, "filters": [],
        "datasourceStates": {"formBased": {"layers": {layer: {
            "columns": {
                "col1": {"label": f"Top {size} {field}", "dataType": "string",
                         "operationType": "terms", "scale": "ordinal",
                         "sourceField": field, "isBucketed": True,
                         "params": {"size": size,
                                    "orderBy": {"type": "column", "columnId": "col2"},
                                    "orderDirection": "desc", "otherBucket": False,
                                    "missingBucket": False}},
                "col2": {"label": "Count", "dataType": "number", "operationType": "count",
                         "isBucketed": False, "scale": "ratio",
                         "sourceField": "___records___"}},
            "columnOrder": ["col1", "col2"], "incompleteColumns": {}}}}},
    }
    return {"id": obj_id, "type": "lens",
            "attributes": {"title": title, "visualizationType": "lnsXY", "state": state},
            "references": [{"type": "index-pattern", "id": dv, "name": _layer_ref()}],
            "managed": False}


def timeseries(obj_id, title, dv, query, split_field=None, series="line"):
    layer = "layer1"
    cols = {
        "col1": {"label": "@timestamp", "dataType": "date",
                 "operationType": "date_histogram", "sourceField": "@timestamp",
                 "isBucketed": True, "scale": "interval", "params": {"interval": "auto"}},
        "col2": {"label": "Count", "dataType": "number", "operationType": "count",
                 "isBucketed": False, "scale": "ratio", "sourceField": "___records___"},
    }
    order = ["col1", "col2"]
    cfg = {"layerId": layer, "layerType": "data", "seriesType": series,
           "xAccessor": "col1", "accessors": ["col2"]}
    if split_field:
        cols["col3"] = {"label": f"Top values of {split_field}", "dataType": "string",
                        "operationType": "terms", "scale": "ordinal",
                        "sourceField": split_field, "isBucketed": True,
                        "params": {"size": 5,
                                   "orderBy": {"type": "column", "columnId": "col2"},
                                   "orderDirection": "desc", "otherBucket": True,
                                   "missingBucket": False}}
        order = ["col1", "col3", "col2"]
        cfg["splitAccessor"] = "col3"
    state = {
        "visualization": {"preferredSeriesType": series,
                          "legend": {"isVisible": True, "position": "right"},
                          "layers": [cfg], "valueLabels": "hide"},
        "query": {"query": query, "language": "kuery"}, "filters": [],
        "datasourceStates": {"formBased": {"layers": {layer: {
            "columns": cols, "columnOrder": order, "incompleteColumns": {}}}}},
    }
    return {"id": obj_id, "type": "lens",
            "attributes": {"title": title, "visualizationType": "lnsXY", "state": state},
            "references": [{"type": "index-pattern", "id": dv, "name": _layer_ref()}],
            "managed": False}


def table(obj_id, title, dv, query, columns):
    layer = "layer1"
    cols, order = {}, []
    for i, (label, field, op) in enumerate(columns):
        cid = f"col{i+1}"
        if op == "terms":
            cols[cid] = {"label": label, "dataType": "string", "operationType": "terms",
                         "sourceField": field, "isBucketed": True,
                         "params": {"size": 15,
                                    "orderBy": {"type": "alphabetical"},
                                    "orderDirection": "asc", "otherBucket": True,
                                    "missingBucket": False}}
        elif op == "unique_count":
            cols[cid] = {"label": label, "dataType": "number",
                         "operationType": "unique_count", "sourceField": field,
                         "isBucketed": False}
        elif op == "max":
            cols[cid] = {"label": label, "dataType": "number", "operationType": "max",
                         "sourceField": field, "isBucketed": False}
        else:
            cols[cid] = {"label": label, "dataType": "number", "operationType": "count",
                         "isBucketed": False, "sourceField": "___records___"}
        order.append(cid)
    state = {
        "visualization": {"layerId": layer, "layerType": "data",
                          "columns": [{"columnId": c} for c in order]},
        "query": {"query": query, "language": "kuery"}, "filters": [],
        "datasourceStates": {"formBased": {"layers": {layer: {
            "columns": cols, "columnOrder": order, "incompleteColumns": {}}}}},
    }
    return {"id": obj_id, "type": "lens",
            "attributes": {"title": title, "visualizationType": "lnsDatatable", "state": state},
            "references": [{"type": "index-pattern", "id": dv, "name": _layer_ref()}],
            "managed": False}


SEC, ALL, CHAIN = "sentinel-logs-security", "sentinel-logs-all", "sentinel-logs-chain"

panels_security = [
    metric("sec-m-failed", "Failed logins", SEC,
           "event.category:authentication and event.outcome:failure", "#BD271E"),
    metric("sec-m-success", "Successful logins", SEC,
           "event.category:authentication and event.outcome:success", "#54B399"),
    metric("sec-m-blocked", "Blocked payloads", SEC, "event.action:payload_blocked", "#D6BF57"),
    metric("sec-m-locked", "Accounts locked", SEC, "event.action:account_locked", "#DA8B45"),
    timeseries("sec-ts-auth", "Authentication outcome over time", SEC,
               "event.category:authentication", split_field="event.outcome"),
    terms_bar("sec-bar-srcip", "Top sources of failed logins", SEC, "source.ip",
              "event.category:authentication and event.outcome:failure"),
    terms_bar("sec-bar-user", "Most targeted accounts", SEC, "user.name",
              "event.category:authentication and event.outcome:failure"),
    terms_bar("sec-bar-sig", "Attack signatures matched", SEC, "rule.name",
              "event.action:payload_blocked"),
    table("sec-geo", "Failed logins by country", SEC,
          "event.category:authentication and event.outcome:failure",
          [("Country", "source.geo.country_name", "terms"),
           ("Unique IPs", "source.ip", "unique_count"), ("Events", "", "count")]),
    terms_bar("sec-bar-ua", "Client type on failed auth", SEC, "user_agent.category",
              "event.category:authentication and event.outcome:failure", size=5),
]

panels_ops = [
    metric("ops-m-total", "Total events", ALL, "*", "#6092C0"),
    metric("ops-m-errors", "Errors", ALL, "log.level:error or log.level:fatal", "#BD271E"),
    metric("ops-m-5xx", "5xx responses", ALL, "http.response.status_class:5xx", "#DA8B45"),
    metric("ops-m-slow", "Slow requests", ALL, "event.action:slow_request", "#D6BF57"),
    timeseries("ops-ts-volume", "Ingest volume by dataset", ALL, "*",
               split_field="event.dataset"),
    timeseries("ops-ts-status", "HTTP status class over time", ALL,
               "http.response.status_class:*", split_field="http.response.status_class"),
    terms_bar("ops-bar-path", "Busiest endpoints", ALL, "url.path", "url.path:*"),
    terms_bar("ops-bar-err", "Errors by type", ALL, "error.type", "error.type:*"),
    terms_bar("ops-bar-svc", "Events by service", ALL, "service.name", "*", size=8),
    timeseries("ops-ts-unparsed", "Unparsed events (parser health)", ALL,
               "tags:parsed\\:none or tags:_grokparsefailure_nginx"),
]

# --- Blockchain ------------------------------------------------------------
# Ordered so the first row is the four numbers a node operator checks first:
# slashing is existential, admin RPC probes mean someone found the node,
# deep reorgs mean consensus trouble, missed duties cost money continuously.
panels_chain = [
    metric("bc-m-slash", "Slashable offences", CHAIN,
           "event.action:slashable_offence", "#BD271E"),
    metric("bc-m-rpcunauth", "Blocked admin RPC calls", CHAIN,
           "event.action:rpc_unauthorized", "#DA8B45"),
    metric("bc-m-reorg", "Deep reorgs", CHAIN,
           "event.action:chain_reorg and blockchain.reorg_depth > 2", "#D6BF57"),
    metric("bc-m-missed", "Missed duties", CHAIN, "event.action:duty_missed", "#6092C0"),

    timeseries("bc-ts-blocks", "Block production by node", CHAIN,
               "event.action:block_proposed", split_field="blockchain.node_id"),
    table("bc-tbl-slash", "Slashing evidence", CHAIN, "event.action:slashable_offence",
          [("Validator", "blockchain.validator.index", "terms"),
           ("Offence", "blockchain.slashing.kind", "terms"),
           ("Slot", "blockchain.slot", "max"), ("Count", "", "count")]),

    terms_bar("bc-bar-rpcmethod", "Restricted RPC methods probed", CHAIN,
              "blockchain.rpc.method", "event.action:rpc_unauthorized"),
    terms_bar("bc-bar-rpcsrc", "Sources probing admin namespaces", CHAIN,
              "source.ip", "event.action:rpc_unauthorized"),

    terms_bar("bc-bar-reject", "Block rejection reasons", CHAIN,
              "blockchain.rejection_reason", "event.action:block_rejected"),
    terms_bar("bc-bar-peer", "Peers sending invalid blocks", CHAIN,
              "blockchain.peer.id", "event.action:block_rejected"),

    timeseries("bc-ts-rpc", "RPC request volume by method", CHAIN,
               "event.action:rpc_request", split_field="blockchain.rpc.method"),
    timeseries("bc-ts-finality", "Epoch finalization", CHAIN,
               "event.action:epoch_finalized", series="bar_stacked"),
]

objects.extend(panels_security + panels_ops + panels_chain)


def dashboard(dash_id, title, description, panels):
    refs, grid = [], []
    x = y = 0
    for i, p in enumerate(panels):
        w, h = (12, 8) if p["attributes"]["visualizationType"] == "lnsMetric" else (24, 15)
        if x + w > 48:
            x, y = 0, y + h
        pid = f"panel-{i}"
        grid.append({"version": "8.13.0", "type": "lens",
                     "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                     "panelIndex": pid, "embeddableConfig": {"enhancements": {}},
                     "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": "lens", "id": p["id"]})
        x += w
    return {"id": dash_id, "type": "dashboard",
            "attributes": {
                "title": title, "description": description,
                "panelsJSON": json.dumps(grid),
                "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True,
                                           "syncColors": True}),
                "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
                "refreshInterval": {"pause": False, "value": 30000},
                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []})}},
            "references": refs, "managed": False}


objects.append(dashboard(
    "sentinel-security-overview", "Sentinel - Security Overview",
    "Authentication outcomes, attack signatures, and the sources behind them.",
    panels_security))
objects.append(dashboard(
    "sentinel-operational-overview", "Sentinel - Operational Overview",
    "Ingest volume, error rates, endpoint traffic and parser health. The "
    "unparsed-events panel is the one to watch after any upstream format change.",
    panels_ops))
objects.append(dashboard(
    "sentinel-blockchain-overview", "Sentinel - Blockchain Node Security",
    "Consensus health and node attack surface. The top row is the operator's "
    "first look: slashing evidence, administrative RPC probing, deep "
    "reorganisations, and missed validator duties.",
    panels_chain))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as fh:
    for obj in objects:
        fh.write(json.dumps(obj) + "\n")
    fh.write(json.dumps({"exportedCount": len(objects), "missingRefCount": 0,
                         "missingReferences": []}) + "\n")

from collections import Counter
print(f"wrote {len(objects)} saved objects to {os.path.relpath(OUT, ROOT)}")
print(dict(Counter(o["type"] for o in objects)))
for o in objects:
    if o["type"] == "dashboard":
        n = len(json.loads(o["attributes"]["panelsJSON"]))
        assert n == len(o["references"]), f"{o['id']}: panel/ref mismatch"
        print(f"  {o['attributes']['title']}: {n} panels")
