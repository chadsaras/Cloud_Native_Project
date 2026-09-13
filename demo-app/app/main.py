"""payments-api - a deliberately noisy demo service.

It exists to produce a realistic, security-relevant log stream: successful and
failed logins, lockouts, role changes, blocked attack payloads, bulk data
reads, slow requests and 5xx errors. The observability platform is the product;
this is the thing being observed.
"""

import os
import random
import re
import time
from collections import defaultdict, deque
from urllib.parse import unquote_plus

from flask import Flask, g, jsonify, request

from . import security_events as sec
from .logging_setup import configure_logging, new_trace_id, trace_id_var

log = configure_logging()
app = Flask(__name__)

# --- Toy identity store -----------------------------------------------------
# Plaintext credentials are fine here and only here: this service holds no real
# data and is never exposed outside the cluster. Anything resembling a real
# secret would end up indexed in Elasticsearch by design.
USERS = {
    "a.sharma":  {"password": "demo-pass-1", "role": "analyst"},
    "r.iyer":    {"password": "demo-pass-2", "role": "analyst"},
    "m.khan":    {"password": "demo-pass-3", "role": "admin"},
    "svc-batch": {"password": "demo-pass-4", "role": "service"},
}

LOCKOUT_THRESHOLD = int(os.getenv("LOCKOUT_THRESHOLD", "5"))
LOCKOUT_WINDOW_SEC = int(os.getenv("LOCKOUT_WINDOW_SEC", "300"))

# username -> deque of failure timestamps. In-memory on purpose: a single
# replica demo does not need shared state, and pretending otherwise would mean
# shipping a Redis nobody looks at.
_failures: dict[str, deque] = defaultdict(deque)
_locked_until: dict[str, float] = {}

# --- Crude request inspection ----------------------------------------------
# A real deployment puts a WAF in front. These patterns exist so the pipeline
# has genuine intrusion_detection events to carry, not to be a WAF.
ATTACK_SIGNATURES = [
    ("sqli.union_select",   re.compile(r"union\s+select|'\s*or\s*'1'\s*=\s*'1", re.I)),
    ("traversal.dotdot",    re.compile(r"\.\./|\.\.%2f", re.I)),
    ("xss.script_tag",      re.compile(r"<script|javascript:", re.I)),
    ("cmdi.shell_meta",     re.compile(r";\s*(cat|ls|whoami|curl)\s|\|\s*sh\b", re.I)),
]


def client_ip() -> str:
    """Trust X-Forwarded-For only because nginx sits directly in front.

    The leftmost entry is the client; everything after is proxy chain. If this
    ever moved behind an untrusted proxy this would be spoofable and would need
    to switch to a trusted-hop count.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def scan_request() -> tuple[str, str] | None:
    """Return (signature_name, sample) if the request looks hostile.

    The raw target is scanned *and* a percent-decoded copy of it. Both are
    necessary:

      - In a query string `+` means a space and `%20` means a space, so
        `union+select` and `union%20select` are the same attack as
        `union select`. Scanning only the raw text misses both, which is the
        single most common way a naive signature check gets bypassed.
      - Decoding alone is not enough either: decoding can *create* a match that
        was not really there, and an attacker can double-encode. Scanning the
        raw form too keeps literal payloads visible.
    """
    raw = f"{request.full_path} {request.get_data(as_text=True)[:2000]}"

    # unquote_plus handles both %XX escapes and `+` as space. One pass only -
    # recursively decoding until stable is what lets a double-encoded payload
    # match a signature the server would never actually have executed.
    decoded = unquote_plus(raw)

    for name, pattern in ATTACK_SIGNATURES:
        for candidate in (raw, decoded):
            match = pattern.search(candidate)
            if match:
                return name, match.group(0)
    return None


@app.before_request
def start_request():
    g.started = time.perf_counter()
    # Honour an inbound trace id so the id survives across services; mint one
    # otherwise. Same header nginx logs, which is what lets us join the two.
    incoming = request.headers.get("X-Request-Id")
    trace_id_var.set(incoming or new_trace_id())

    hit = scan_request()
    if hit:
        signature, sample = hit
        sec.suspicious_payload(request.path, client_ip(), signature, sample)
        return jsonify({"error": "request rejected"}), 400


@app.after_request
def finish_request(response):
    elapsed_ms = (time.perf_counter() - getattr(g, "started", time.perf_counter())) * 1000
    # Slow requests get their own log line at WARN so latency detections do not
    # have to aggregate over every single request to find the tail.
    if elapsed_ms > 1000:
        log.warning(
            "Slow request %s %s took %.0fms", request.method, request.path, elapsed_ms,
            extra={"ecs": {
                "event": {"kind": "event", "category": ["web"],
                          "action": "slow_request", "duration": int(elapsed_ms * 1e6),
                          "dataset": "app.performance"},
                "http": {"request": {"method": request.method},
                         "response": {"status_code": response.status_code}},
                "url": {"path": request.path},
                "source": {"ip": client_ip()},
            }},
        )
    response.headers["X-Request-Id"] = trace_id_var.get()
    return response


@app.route("/healthz")
def healthz():
    """Liveness probe. Deliberately does not log - probes every 10s would
    otherwise dominate the index and teach the wrong lesson about volume."""
    return jsonify({"status": "ok"}), 200


@app.route("/readyz")
def readyz():
    return jsonify({"status": "ready", "version": os.getenv("SERVICE_VERSION", "1.4.2")}), 200


@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    ip = client_ip()
    ua = request.headers.get("User-Agent", "-")
    now = time.time()

    if _locked_until.get(username, 0) > now:
        sec.auth_failure(username, ip, ua, "account_locked")
        return jsonify({"error": "account locked"}), 423

    record = USERS.get(username)
    if record and record["password"] == password:
        _failures.pop(username, None)
        sec.auth_success(username, ip, ua, trace_id_var.get())
        return jsonify({"token": f"demo-token-{new_trace_id()}", "role": record["role"]}), 200

    reason = "unknown_user" if not record else "bad_password"
    sec.auth_failure(username, ip, ua, reason)

    # Slide the failure window forward, then decide on lockout.
    window = _failures[username]
    window.append(now)
    while window and now - window[0] > LOCKOUT_WINDOW_SEC:
        window.popleft()

    if len(window) >= LOCKOUT_THRESHOLD:
        _locked_until[username] = now + LOCKOUT_WINDOW_SEC
        sec.account_locked(username, ip, len(window))
        window.clear()

    return jsonify({"error": "invalid credentials"}), 401


@app.route("/api/users/<username>/role", methods=["PUT"])
def change_role(username: str):
    body = request.get_json(silent=True) or {}
    actor = request.headers.get("X-Actor", "unknown")
    new_role = str(body.get("role", "analyst"))
    sec.privilege_change(actor, username, new_role, client_ip())
    return jsonify({"user": username, "role": new_role}), 200


@app.route("/api/customers")
def list_customers():
    limit = min(int(request.args.get("limit", 25)), 5000)
    actor = request.headers.get("X-Actor", "anonymous")
    # Large reads are the interesting ones; small reads are ordinary traffic.
    if limit >= 500:
        sec.data_access(actor, limit, "customers", client_ip())
    return jsonify({"count": limit, "items": []}), 200


@app.route("/api/checkout", methods=["POST"])
def checkout():
    """Main business endpoint. Fails and stalls at a configurable rate so the
    dashboards have a real error-rate and latency signal to chart."""
    error_rate = float(os.getenv("SIMULATED_ERROR_RATE", "0.04"))
    slow_rate = float(os.getenv("SIMULATED_SLOW_RATE", "0.06"))

    # Chaos hook. Lets a test drive a deterministic error spike instead of
    # waiting for a 4% random rate to produce 50 failures, which at demo
    # traffic levels would take roughly 20 minutes.
    #
    # Gated by an env flag that a real deployment sets to false. The header is
    # deliberately not a query parameter: query strings end up in the nginx
    # access log and in dashboards, where a synthetic failure would be
    # indistinguishable from a real one.
    if os.getenv("CHAOS_ENABLED", "true").lower() == "true" and \
            request.headers.get("X-Chaos-Fail"):
        log.error(
            "Checkout failed (chaos-injected)",
            extra={"ecs": {
                "event": {"kind": "event", "category": ["web"],
                          "action": "checkout_failed", "outcome": "failure",
                          "dataset": "app.checkout"},
                "source": {"ip": client_ip()},
                "labels": {"chaos_injected": True},
            }},
        )
        return jsonify({"error": "internal error"}), 500

    if random.random() < slow_rate:
        time.sleep(random.uniform(1.1, 2.4))

    if random.random() < error_rate:
        try:
            raise RuntimeError("upstream ledger service returned 503")
        except RuntimeError:
            log.exception(
                "Checkout failed for order",
                extra={"ecs": {
                    "event": {"kind": "event", "category": ["web"],
                              "action": "checkout_failed", "outcome": "failure",
                              "dataset": "app.checkout"},
                    "source": {"ip": client_ip()},
                }},
            )
        return jsonify({"error": "internal error"}), 500

    amount = round(random.uniform(5, 900), 2)
    log.info(
        "Checkout completed for %.2f", amount,
        extra={"ecs": {
            "event": {"kind": "event", "category": ["web"],
                      "action": "checkout_completed", "outcome": "success",
                      "dataset": "app.checkout"},
            "source": {"ip": client_ip()},
            "labels": {"amount": amount, "currency": "INR"},
        }},
    )
    return jsonify({"status": "confirmed", "amount": amount}), 200


if __name__ == "__main__":
    log.info(
        "payments-api starting",
        extra={"ecs": {"event": {"kind": "event", "category": ["process"],
                                 "type": ["start"], "action": "service_start"}}},
    )
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
