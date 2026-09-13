"""Helpers that emit ECS security events.

Every function here maps onto an ECS event categorisation so the detection
rules can key off `event.category` / `event.type` / `event.outcome` instead of
matching on free-text messages. Matching on message text is how detections rot:
someone rewords a log line and the rule silently stops firing.

Reference: https://www.elastic.co/guide/en/ecs/current/ecs-category-field-values-reference.html
"""

import logging

log = logging.getLogger("payments-api.security")


def auth_success(username: str, source_ip: str, user_agent: str, trace_id: str) -> None:
    log.info(
        "Authentication succeeded for user %s", username,
        extra={"ecs": {
            "event": {
                "kind": "event",
                "category": ["authentication"],
                "type": ["start"],
                "action": "user_login",
                "outcome": "success",
                "dataset": "app.auth",
            },
            "user": {"name": username},
            "source": {"ip": source_ip},
            "user_agent": {"original": user_agent},
        }},
    )


def auth_failure(username: str, source_ip: str, user_agent: str, reason: str) -> None:
    log.warning(
        "Authentication failed for user %s: %s", username, reason,
        extra={"ecs": {
            "event": {
                "kind": "alert",
                "category": ["authentication"],
                "type": ["start"],
                "action": "user_login",
                "outcome": "failure",
                "reason": reason,
                "dataset": "app.auth",
            },
            "user": {"name": username},
            "source": {"ip": source_ip},
            "user_agent": {"original": user_agent},
        }},
    )


def account_locked(username: str, source_ip: str, attempts: int) -> None:
    """Emitted when the app's own lockout threshold trips.

    This is a useful control event for the platform: a detection that fires on
    brute force should normally be *preceded* by one of these. If we alert on
    brute force and there is no lockout event, either the lockout is broken or
    the attacker found a path that bypasses it. Both are worth knowing.
    """
    log.error(
        "Account %s locked after %d consecutive failures", username, attempts,
        extra={"ecs": {
            "event": {
                "kind": "alert",
                "category": ["authentication", "iam"],
                "type": ["user", "change"],
                "action": "account_locked",
                "outcome": "success",
                "severity": 73,
                "dataset": "app.auth",
            },
            "user": {"name": username},
            "source": {"ip": source_ip},
            "labels": {"failed_attempts": attempts},
        }},
    )


def privilege_change(actor: str, target: str, new_role: str, source_ip: str) -> None:
    log.warning(
        "User %s granted role %s to %s", actor, new_role, target,
        extra={"ecs": {
            "event": {
                "kind": "event",
                "category": ["iam"],
                "type": ["admin", "change"],
                "action": "role_grant",
                "outcome": "success",
                "dataset": "app.iam",
            },
            "user": {"name": actor, "target": {"name": target}},
            "source": {"ip": source_ip},
            "labels": {"granted_role": new_role},
        }},
    )


def suspicious_payload(path: str, source_ip: str, signature: str, sample: str) -> None:
    """Application-layer attack signature (SQLi / traversal / XSS probe).

    We log the *signature name* plus a truncated sample rather than the whole
    payload. Full attacker payloads in an index that analysts browse is how you
    end up with stored XSS in your own dashboard.
    """
    log.warning(
        "Blocked suspicious request to %s matching %s", path, signature,
        extra={"ecs": {
            "event": {
                "kind": "alert",
                "category": ["web", "intrusion_detection"],
                "type": ["denied"],
                "action": "payload_blocked",
                "outcome": "success",
                "severity": 64,
                "dataset": "app.waf",
            },
            "source": {"ip": source_ip},
            "url": {"path": path},
            "rule": {"name": signature},
            "labels": {"payload_sample": sample[:120]},
        }},
    )


def data_access(username: str, records: int, resource: str, source_ip: str) -> None:
    """Bulk read of customer data - the signal behind exfiltration detections."""
    log.info(
        "User %s read %d records from %s", username, records, resource,
        extra={"ecs": {
            "event": {
                "kind": "event",
                "category": ["database"],
                "type": ["access"],
                "action": "bulk_read",
                "outcome": "success",
                "dataset": "app.data",
            },
            "user": {"name": username},
            "source": {"ip": source_ip},
            "labels": {"record_count": records, "resource": resource},
        }},
    )
