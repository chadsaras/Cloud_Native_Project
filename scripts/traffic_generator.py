#!/usr/bin/env python3
"""Drive realistic traffic against payments-api.

Two modes:
  baseline  - ordinary business traffic with a low, steady rate of noise
  scenario  - inject a specific attack so a named detection fires on demand

The scenarios exist so a demo is reproducible. "Wait around and hope something
interesting shows up" is not a demo; `--scenario brute_force` firing a specific
rule 30 seconds later is.

Usage:
    python3 scripts/traffic_generator.py --target http://localhost:8080 --duration 300
    python3 scripts/traffic_generator.py --scenario brute_force
    python3 scripts/traffic_generator.py --scenario all
"""

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

USERS = ["a.sharma", "r.iyer", "m.khan", "svc-batch"]
PASSWORDS = {
    "a.sharma": "demo-pass-1", "r.iyer": "demo-pass-2",
    "m.khan": "demo-pass-3", "svc-batch": "demo-pass-4",
}

# Residential-looking source ranges for benign traffic. Deliberately drawn from
# documentation/test ranges (RFC 5737 / 3849) so nothing here ever resolves to
# or implicates a real host on the internet.
BENIGN_IPS = [f"203.0.113.{n}" for n in range(2, 60)]
OFFICE_IPS = [f"198.51.100.{n}" for n in range(2, 12)]
ATTACKER_IPS = ["192.0.2.66", "192.0.2.131", "192.0.2.207"]

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) Mobile/15E148 Safari/604.1",
]
TOOLS = ["curl/8.4.0", "python-requests/2.31.0", "sqlmap/1.7.11", "Nikto/2.5.0", "Go-http-client/2.0"]


def call(target, method, path, *, body=None, ip=None, ua=None, actor=None,
         headers=None, timeout=8):
    url = f"{target}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Forwarded-For", ip or random.choice(BENIGN_IPS))
    req.add_header("User-Agent", ua or random.choice(BROWSERS))
    if actor:
        req.add_header("X-Actor", actor)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code          # 4xx/5xx are expected and are the point
    except Exception:
        return 0                 # connection refused etc - caller counts these


# --- Baseline ---------------------------------------------------------------

def baseline_action(target):
    """One unit of ordinary traffic, weighted to look like a real service."""
    roll = random.random()
    ip = random.choice(BENIGN_IPS + OFFICE_IPS)

    if roll < 0.45:
        call(target, "POST", "/api/checkout", body={"cart": random.randint(1, 5)}, ip=ip)
    elif roll < 0.70:
        call(target, "GET", f"/api/customers?limit={random.randint(10, 100)}",
             ip=ip, actor=random.choice(USERS))
    elif roll < 0.92:
        # Mostly good logins, with the ~8% typo rate a real login page sees.
        user = random.choice(USERS)
        pwd = PASSWORDS[user] if random.random() > 0.08 else "wrong-password"
        call(target, "POST", "/api/login", body={"username": user, "password": pwd}, ip=ip)
    else:
        call(target, "GET", "/readyz", ip=ip)


def run_baseline(target, duration, rps):
    print(f"[baseline] {rps} req/s for {duration}s against {target}")
    deadline = time.time() + duration
    sent = 0
    with ThreadPoolExecutor(max_workers=max(4, rps)) as pool:
        while time.time() < deadline:
            tick = time.time()
            for _ in range(rps):
                pool.submit(baseline_action, target)
                sent += 1
            elapsed = time.time() - tick
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)
            if sent % (rps * 15) == 0:
                print(f"  {sent} requests sent, {int(deadline - time.time())}s left")
    print(f"[baseline] done, {sent} requests")


# --- Scenarios --------------------------------------------------------------

def scenario_brute_force(target):
    """Fires: SEC-001 (brute force) and the app's own lockout event."""
    attacker = ATTACKER_IPS[0]
    victim = "m.khan"                       # the admin account, on purpose
    print(f"[brute_force] 40 failures against {victim} from {attacker}")
    for i in range(40):
        call(target, "POST", "/api/login",
             body={"username": victim, "password": f"Password{i}!"},
             ip=attacker, ua="python-requests/2.31.0")
        time.sleep(0.25)


def scenario_password_spray(target):
    """Fires: SEC-002. One password, many accounts - the inverse of brute force
    and the reason a per-account threshold alone is not enough."""
    attacker = ATTACKER_IPS[1]
    sprayed = [f"user{n:03d}" for n in range(1, 46)] + USERS
    print(f"[password_spray] one password across {len(sprayed)} accounts from {attacker}")
    for user in sprayed:
        call(target, "POST", "/api/login",
             body={"username": user, "password": "Winter2025!"},
             ip=attacker, ua="Go-http-client/2.0")
        time.sleep(0.2)


def scenario_web_attack(target):
    """Fires: SEC-004. Classic scanner sweep - SQLi, traversal, XSS, cmdi."""
    attacker = ATTACKER_IPS[2]
    payloads = [
        "/api/customers?id=1'+OR+'1'='1",
        "/api/customers?id=1+UNION+SELECT+username,password+FROM+users",
        "/api/../../../../etc/passwd",
        "/api/customers?q=<script>alert(document.cookie)</script>",
        "/api/checkout?cmd=;cat+/etc/shadow",
        "/api/customers?file=..%2f..%2f..%2fetc%2fhosts",
    ]
    print(f"[web_attack] {len(payloads) * 4} probes from {attacker}")
    for _ in range(4):
        for path in payloads:
            call(target, "GET", path, ip=attacker, ua=random.choice(TOOLS))
            time.sleep(0.15)


def scenario_enumeration(target):
    """Fires: SEC-003. High 404/401 ratio from one source - endpoint discovery."""
    attacker = "192.0.2.44"
    paths = ["/admin", "/.env", "/.git/config", "/wp-login.php", "/api/v1/keys",
             "/actuator/health", "/phpmyadmin", "/backup.sql", "/config.json",
             "/api/internal/debug", "/server-status", "/.aws/credentials"]
    print(f"[enumeration] {len(paths) * 3} unknown paths from {attacker}")
    for _ in range(3):
        for path in paths:
            call(target, "GET", path, ip=attacker, ua="Nikto/2.5.0")
            time.sleep(0.1)


def scenario_data_exfil(target):
    """Fires: SEC-005. A service account pulling customer data in bulk, at a
    volume and hour that does not match its normal batch behaviour."""
    print("[data_exfil] bulk customer reads by svc-batch")
    for _ in range(12):
        call(target, "GET", "/api/customers?limit=5000",
             ip="192.0.2.99", actor="svc-batch", ua="curl/8.4.0")
        time.sleep(0.4)


def scenario_privilege_escalation(target):
    """Fires: SEC-006. Role grants to admin outside change-window."""
    print("[privilege_escalation] role grants to admin")
    for target_user in ["a.sharma", "r.iyer", "user042"]:
        call(target, "PUT", f"/api/users/{target_user}/role",
             body={"role": "admin"}, ip="192.0.2.99", actor="svc-batch")
        time.sleep(0.5)


def scenario_error_spike(target):
    """Fires: OPS-001. Drives a deterministic 5xx burst via the chaos hook.

    OPS-001 needs 50 failures in 5 minutes, a threshold sized for production
    traffic. The app's 4% random error rate would take about 20 minutes to get
    there at demo volume, so this forces them instead of lowering the threshold
    to fit the demo - a rule tuned to make a demo work is a rule that will not
    work in production.
    """
    print("[error_spike] 60 forced 5xx responses")
    for _ in range(60):
        call(target, "POST", "/api/checkout", body={"cart": 1},
             headers={"X-Chaos-Fail": "1"})
        time.sleep(0.05)


SCENARIOS = {
    "brute_force": scenario_brute_force,
    "password_spray": scenario_password_spray,
    "web_attack": scenario_web_attack,
    "enumeration": scenario_enumeration,
    "data_exfil": scenario_data_exfil,
    "privilege_escalation": scenario_privilege_escalation,
    "error_spike": scenario_error_spike,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--duration", type=int, default=120, help="baseline seconds")
    parser.add_argument("--rps", type=int, default=6, help="baseline requests/sec")
    parser.add_argument("--scenario", choices=list(SCENARIOS) + ["all"],
                        help="run an attack scenario instead of baseline")
    args = parser.parse_args()

    if call(args.target, "GET", "/healthz") == 0:
        print(f"error: {args.target} is not reachable", file=sys.stderr)
        return 1

    if args.scenario == "all":
        for name, fn in SCENARIOS.items():
            fn(args.target)
            time.sleep(2)
    elif args.scenario:
        SCENARIOS[args.scenario](args.target)
    else:
        run_baseline(args.target, args.duration, args.rps)
    return 0


if __name__ == "__main__":
    sys.exit(main())
