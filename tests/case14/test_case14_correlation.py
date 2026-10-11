#!/usr/bin/env python3
"""Validate the Case 14 correlation specification against controlled timelines."""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path


STAGES = ("network_logon", "winrm_session", "powershell_execution", "file_decode", "scheduled_task_creation")
MAX_SECONDS = 30 * 60


def basename(value: object) -> str:
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def classify(event: dict[str, object]) -> str | None:
    event_id = int(event.get("event_id", 0))
    image = basename(event.get("image"))
    parent = basename(event.get("parent_image"))
    command = str(event.get("command_line", ""))
    if event_id == 4624 and int(event.get("logon_type", 0)) == 3:
        return "network_logon"
    if event_id == 1 and image == "wsmprovhost.exe":
        return "winrm_session"
    if event_id == 1 and image in {"powershell.exe", "pwsh.exe"} and parent == "wsmprovhost.exe":
        return "powershell_execution"
    if event_id == 1 and image == "certutil.exe" and re.search(r"(?:^|\s)-(?:decode|decodehex)(?:\s|$)", command, re.I):
        return "file_decode"
    if event_id == 1 and image == "schtasks.exe" and re.search(r"(?:^|\s)/create(?:\s|$)", command, re.I):
        return "scheduled_task_creation"
    return None


def parse_time(value: object) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def correlate(
    events: list[dict[str, object]],
    stages: tuple[str, ...],
    max_seconds: int,
) -> tuple[bool, list[str], int | None]:
    ordered = sorted(events, key=lambda event: parse_time(event["timestamp"]))
    if not ordered:
        return False, [], None
    host = str(ordered[0].get("host", ""))
    user = str(ordered[0].get("user", ""))
    matched: list[tuple[str, datetime]] = []
    expected_index = 0
    for event in ordered:
        if str(event.get("host", "")) != host or str(event.get("user", "")) != user:
            continue
        stage = classify(event)
        if stage == stages[expected_index]:
            matched.append((stage, parse_time(event["timestamp"])))
            expected_index += 1
            if expected_index == len(stages):
                elapsed = int((matched[-1][1] - matched[0][1]).total_seconds())
                return elapsed <= max_seconds, [item[0] for item in matched], elapsed
    return False, [item[0] for item in matched], None


def read_spec(path: Path) -> tuple[list[str], tuple[str, ...], int]:
    content = path.read_text(encoding="utf-8")
    required = [
        "title:", "id:", "status:", "type: ordered_temporal_correlation", "timespan: 30m",
        "group_by:", "host", "user", *STAGES,
        "attack.t1021.006", "attack.t1059.001", "attack.t1140", "attack.t1053.005",
    ]
    errors = [f"missing specification token: {token}" for token in required if token not in content]
    match = re.search(r"(?m)^id:\s*([^\s]+)\s*$", content)
    try:
        uuid.UUID(match.group(1) if match else "")
    except ValueError:
        errors.append("invalid or missing specification UUID")
    stage_names = tuple(re.findall(r"(?m)^\s{2}- name:\s*([^\s]+)\s*$", content))
    if stage_names != STAGES:
        errors.append("unexpected ordered stage sequence")
    timespan = re.search(r"(?m)^timespan:\s*(\d+)m\s*$", content)
    max_seconds = int(timespan.group(1)) * 60 if timespan else MAX_SECONDS
    if not timespan:
        errors.append("invalid or missing minute timespan")
    group_block = re.search(r"(?ms)^group_by:\s*\n((?:\s+-\s*[^\n]+\n)+)", content)
    group_fields = re.findall(r"(?m)^\s+-\s*([^\s]+)\s*$", group_block.group(1)) if group_block else []
    if group_fields != ["host", "user"]:
        errors.append("unexpected correlation grouping fields")
    return errors, stage_names or STAGES, max_seconds


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--scenarios", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    errors, stages, max_seconds = read_spec(args.spec)
    scenarios = json.loads(args.scenarios.read_text(encoding="utf-8"))
    results = []
    for scenario in scenarios:
        actual, matched_stages, elapsed_seconds = correlate(scenario["events"], stages, max_seconds)
        expected = bool(scenario["expected"])
        results.append({
            "id": scenario["id"],
            "expected": expected,
            "actual": actual,
            "matched_stages": matched_stages,
            "elapsed_seconds": elapsed_seconds,
            "passed": actual == expected,
        })

    passed = not errors and all(result["passed"] for result in results)
    report = {
        "case": "Case 14 - Multi-Stage Attack Chain",
        "validation_type": "offline ordered-temporal correlation validation",
        "passed": passed,
        "artifact_errors": errors,
        "tests_total": len(results),
        "tests_passed": sum(result["passed"] for result in results),
        "expected_correlations": sum(result["expected"] for result in results),
        "actual_correlations": sum(result["actual"] for result in results),
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
