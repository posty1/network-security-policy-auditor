#!/usr/bin/env python3
"""Review synthetic firewall-policy exports for common control gaps."""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path


def findings_for(rule: dict) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if rule.get("source") in {"any", "0.0.0.0/0"}:
        findings.append(("HIGH", "broad source scope"))
    if rule.get("destination") in {"any", "0.0.0.0/0"}:
        findings.append(("HIGH", "broad destination scope"))
    if rule.get("service") == "any":
        findings.append(("HIGH", "service is any"))
    if not rule.get("logging_enabled"):
        findings.append(("HIGH", "logging is disabled"))
    if not rule.get("owner") or not rule.get("change_ticket"):
        findings.append(("MEDIUM", "missing owner or change ticket"))
    expires = rule.get("expires_on")
    if expires and date.fromisoformat(expires) < date.today():
        findings.append(("MEDIUM", f"temporary rule expired on {expires}"))
    return findings


def main(path: str) -> int:
    rules = json.loads(Path(path).read_text())
    total = 0
    for rule in rules:
        for severity, message in findings_for(rule):
            total += 1
            print(f"[{severity}] {rule['id']}: {message}")
    print(f"\nReviewed {len(rules)} rules; found {total} item(s).")
    return 1 if any(severity == "HIGH" for rule in rules for severity, _ in findings_for(rule)) else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 policy_auditor.py sample_rules.json")
    raise SystemExit(main(sys.argv[1]))
