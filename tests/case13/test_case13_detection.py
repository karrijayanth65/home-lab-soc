#!/usr/bin/env python3
"""Validate the Case 13 rule artifacts and detection logic against JSONL fixtures."""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path


DECODE_ARGUMENT = re.compile(r"(?:^|\s)-(?:decode|decodehex)(?:\s|$)", re.IGNORECASE)
REQUIRED_SIGMA_KEYS = (
    "title:",
    "id:",
    "status:",
    "logsource:",
    "detection:",
    "falsepositives:",
    "level:",
)


def matches(event: dict[str, str]) -> bool:
    image = str(event.get("Image", "")).replace("/", "\\").lower()
    original_name = str(event.get("OriginalFileName", "")).lower()
    command_line = str(event.get("CommandLine", ""))
    image_match = image.endswith("\\certutil.exe") or image == "certutil.exe"
    original_name_match = original_name == "certutil.exe"
    return (image_match or original_name_match) and bool(DECODE_ARGUMENT.search(command_line))


def validate_sigma(path: Path) -> list[str]:
    content = path.read_text(encoding="utf-8")
    errors = [f"missing top-level Sigma key: {key}" for key in REQUIRED_SIGMA_KEYS if not re.search(rf"(?m)^{re.escape(key)}", content)]
    match = re.search(r"(?m)^id:\s*([^\s]+)\s*$", content)
    if not match:
        errors.append("missing Sigma UUID")
    else:
        try:
            uuid.UUID(match.group(1))
        except ValueError:
            errors.append("invalid Sigma UUID")
    for token in ("Image|endswith", "OriginalFileName", "CommandLine|contains", "selection_image and selection_decode", "attack.t1140"):
        if token not in content:
            errors.append(f"missing Sigma detection token: {token}")
    return errors


def read_wazuh_rule(path: Path) -> tuple[list[str], re.Pattern[str] | None, re.Pattern[str] | None]:
    errors: list[str] = []
    root = ET.parse(path).getroot()
    rule = root.find("rule")
    if rule is None:
        return ["missing Wazuh rule"], None, None
    if rule.get("id") != "100201":
        errors.append("unexpected Wazuh rule ID")
    if rule.get("level") != "8":
        errors.append("unexpected Wazuh rule level")
    if rule.findtext("if_sid") != "61603":
        errors.append("unexpected Wazuh parent rule")
    fields = {field.get("name"): field.text or "" for field in rule.findall("field")}
    if "win.eventdata.image" not in fields or "certutil" not in fields["win.eventdata.image"].lower():
        errors.append("Wazuh image condition is missing")
    if "win.eventdata.commandLine" not in fields or "decode" not in fields["win.eventdata.commandLine"].lower():
        errors.append("Wazuh command-line condition is missing")
    if rule.findtext("mitre/id") != "T1140":
        errors.append("Wazuh MITRE mapping is missing")
    try:
        image_pattern = re.compile(fields["win.eventdata.image"])
        command_pattern = re.compile(fields["win.eventdata.commandLine"])
    except (KeyError, re.error) as exc:
        errors.append(f"invalid Wazuh regular expression: {exc}")
        image_pattern = None
        command_pattern = None
    return errors, image_pattern, command_pattern


def load_fixtures(path: Path) -> list[dict[str, object]]:
    fixtures = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            fixture = json.loads(line)
            if not {"id", "expected", "event"}.issubset(fixture):
                raise ValueError(f"fixture line {number} is missing required fields")
            fixtures.append(fixture)
    return fixtures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sigma", type=Path, required=True)
    parser.add_argument("--wazuh", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    wazuh_errors, wazuh_image_pattern, wazuh_command_pattern = read_wazuh_rule(args.wazuh)
    artifact_errors = validate_sigma(args.sigma) + wazuh_errors
    cases = []
    for fixture in load_fixtures(args.fixtures):
        event = fixture["event"]
        sigma_actual = matches(event)
        wazuh_actual = bool(
            wazuh_image_pattern
            and wazuh_command_pattern
            and wazuh_image_pattern.search(str(event.get("Image", "")))
            and wazuh_command_pattern.search(str(event.get("CommandLine", "")))
        )
        expected = bool(fixture["expected"])
        cases.append({
            "id": fixture["id"],
            "expected": expected,
            "sigma_actual": sigma_actual,
            "wazuh_actual": wazuh_actual,
            "passed": sigma_actual == expected and wazuh_actual == expected,
        })

    passed = not artifact_errors and all(case["passed"] for case in cases)
    report = {
        "case": "Case 13 - Custom Detection Engineering",
        "validation_type": "offline rule-artifact and fixture validation",
        "passed": passed,
        "artifact_errors": artifact_errors,
        "tests_total": len(cases),
        "tests_passed": sum(case["passed"] for case in cases),
        "expected_matches": sum(case["expected"] for case in cases),
        "sigma_actual_matches": sum(case["sigma_actual"] for case in cases),
        "wazuh_actual_matches": sum(case["wazuh_actual"] for case in cases),
        "results": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
