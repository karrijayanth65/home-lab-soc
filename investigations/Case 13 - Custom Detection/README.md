# Case 13 — Custom Detection Engineering

> **Case type:** Detection engineering and rule validation<br>
> **Detection:** Sigma and Wazuh custom rule for `certutil.exe` file decoding<br>
> **Severity:** Medium in Sigma; Wazuh level `8`<br>
> **Status:** Closed — rule artifacts created and offline validation passed<br>
> **Environment:** Repository-based detection-as-code validation<br>
> **Validation date:** 12 October 2026 (IST)<br>
> **Evidence mode:** Executed offline fixture tests plus supporting diagrams<br>
> **Confidence:** High for the tested matching logic; medium for production portability

> [!NOTE]
> The repository test suite executed the detection logic against six controlled fixtures and passed all six. This validates the stored rule logic and expected matches. It does not substitute for `wazuh-logtest`, manager deployment, field-mapping confirmation, or alert review on an installed Wazuh server.

## Executive Summary

Case 13 converts the `certutil.exe` decoding behavior from Cases 11 and 12 into portable and platform-specific detection artifacts. The implementation includes a Sigma process-creation rule, Wazuh custom rule `100201`, six positive and negative JSON fixtures, a reusable Python validator, and a machine-readable result file. The validator checked both rule artifacts and executed the shared matching logic against every fixture; all six tests passed, including two expected detections and four expected non-matches. The analyst verdict is that the rule logic is validated for its documented offline scope and ready for Wazuh runtime testing when a manager is available.

## 1. Objective and Scope

The objective is to detect Windows process creation where:

1. the process image is `certutil.exe`, or its original filename is `CertUtil.exe`; and
2. the command line contains `-decode` or `-decodehex` as a distinct argument.

The rule intentionally does not match `-encode`, `-hashfile`, certificate-store verification, or command text merely mentioning `certutil.exe` from another process. This keeps the detection focused on file-decoding behavior while retaining administrative false positives for analyst review.

The scope includes:

- a portable Sigma rule;
- a Wazuh Sysmon rule;
- deterministic positive and negative fixtures;
- repeatable offline validation;
- severity, false-positive, ATT&CK, and triage guidance;
- deployment instructions for later Wazuh runtime validation.

## 2. Detection Lifecycle

![Case 13 detection lifecycle](../../screenshots/Case%2013%20-%20Custom%20Detection/01-case13-detection-lifecycle.png)

```text
Behavior definition
    ↓
Required process evidence
    ↓
Portable Sigma logic
    ↓
Wazuh rule 100201
    ↓
Positive and negative fixtures
    ↓
Offline validation
    ↓
Wazuh deployment validation
```

## 3. Detection Artifacts

| Artifact | Purpose | Validation state |
|---|---|---|
| [Sigma rule](../../detections/sigma/windows/process_creation/case13_certutil_file_decode.yml) | Portable Windows process-creation detection | Structure and required selectors checked |
| [Wazuh rule](../../detections/wazuh/case13_certutil_decode.xml) | Sysmon Event `1` implementation using custom rule `100201` | XML structure and required fields checked |
| [JSONL fixtures](../../tests/case13/fixtures.jsonl) | Two expected matches and four expected non-matches | All fixtures executed |
| [Python validator](../../tests/case13/test_case13_detection.py) | Repeatable artifact and matching-logic validation | Executed successfully |
| [Validation result](../../tests/case13/results.json) | Machine-readable test evidence | `passed: true`, six of six tests passed |

## 4. Required Evidence

| Field | Purpose |
|---|---|
| Process image or original filename | Identifies `certutil.exe`, including renamed copies when original filename is available |
| Full command line | Distinguishes decoding from hashing, verification, encoding, or unrelated use |
| Parent process | Helps separate administrative activity from suspicious scripting or application ancestry |
| User and host | Establishes authorization, endpoint role, and baseline |
| Input and output paths | Supports file provenance, location risk, and follow-on investigation |
| Process identifier or GUID | Connects process creation to related file and child-process events |
| Event and ingestion times | Supports sequence and pipeline-delay analysis |

The Sigma rule uses a generic Windows `process_creation` log source so it can map to Sysmon Event `1`, Security Event `4688`, or another product that supplies equivalent fields. The Wazuh rule is deliberately narrower and inherits from Sysmon Event `1` parent rule `61603`.

## 5. Sigma Rule

The Sigma rule is stored at:

```text
detections/sigma/windows/process_creation/case13_certutil_file_decode.yml
```

Its central logic is:

```yaml
detection:
    selection_image:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_decode:
        CommandLine|contains:
            - ' -decode '
            - ' -decodehex '
    condition: selection_image and selection_decode
```

The rule status is `test` because backend conversion, field mapping, and deployment must still be confirmed for each target SIEM. The rule maps to MITRE ATT&CK `T1140`.

## 6. Wazuh Rule

The Wazuh rule is stored at:

```text
detections/wazuh/case13_certutil_decode.xml
```

Rule `100201` uses Wazuh's recommended custom-rule ID range and inherits from the built-in Sysmon Event `1` rule:

```xml
<rule id="100201" level="8">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\certutil\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(?:^|\s)-(?:decode|decodehex)(?:\s|$)</field>
  <description>Case 13: certutil.exe decoded a file on $(win.system.computer)</description>
  <mitre>
    <id>T1140</id>
  </mitre>
</rule>
```

The installed Wazuh version must be checked before deployment because parent-rule IDs and decoded field names can change. The rule file preserves that dependency in its header comment.

## 7. Detection Logic

![Case 13 rule logic](../../screenshots/Case%2013%20-%20Custom%20Detection/02-case13-rule-logic.png)

```text
Windows process creation
    ↓
Is the image certutil.exe?
    ├── No  → no match
    └── Yes
          ↓
Does the command line contain -decode or -decodehex?
    ├── No  → no match
    └── Yes → medium-priority detection
```

The detection identifies behavior. The analyst still needs parent process, user, host, paths, file content, authorization, and follow-on execution to determine intent.

## 8. Test Design

The fixture set covers the primary match path, case-insensitive handling, and four common non-match paths.

| Fixture | Expected | Reason |
|---|---|---|
| `positive_decode_temp` | Match | `certutil.exe` uses `-decode` on an inert temporary file |
| `positive_decodehex_case_insensitive` | Match | Uppercase image and `-DECODEHEX` verify case-insensitive logic |
| `negative_hashfile` | No match | Hash calculation is outside this rule's decode scope |
| `negative_encode_only` | No match | Encoding alone is excluded to reduce noise |
| `negative_wrong_process` | No match | PowerShell text mentions the command, but the process image is not `certutil.exe` |
| `negative_verify_store` | No match | Certificate-store verification is outside the decode scope |

## 9. Executed Validation

The following command executed the repository test suite:

```powershell
python tests/case13/test_case13_detection.py `
  --sigma detections/sigma/windows/process_creation/case13_certutil_file_decode.yml `
  --wazuh detections/wazuh/case13_certutil_decode.xml `
  --fixtures tests/case13/fixtures.jsonl `
  --output tests/case13/results.json
```

The stored result reports:

```json
{
  "validation_type": "offline rule-artifact and fixture validation",
  "passed": true,
  "artifact_errors": [],
  "tests_total": 6,
  "tests_passed": 6,
  "expected_matches": 2,
  "sigma_actual_matches": 2,
  "wazuh_actual_matches": 2
}
```

![Case 13 test results](../../screenshots/Case%2013%20-%20Custom%20Detection/03-case13-test-results.png)

### Validation outcome

- Sigma structure checks: passed
- Sigma required selectors and condition: passed
- Sigma UUID: valid
- Wazuh XML parsing: passed
- Wazuh rule ID, level, parent, fields, and ATT&CK mapping checks: passed
- Fixture results: `6/6` passed
- Expected matches: `2`
- Sigma actual matches: `2`
- Wazuh-regex actual matches: `2`
- Unexpected matches: `0`
- Missed expected matches: `0`

## 10. Tuning Decisions

### Included

- `certutil.exe -decode`
- `certutil.exe -decodehex`
- case-insensitive image and argument matching
- renamed image coverage in Sigma when `OriginalFileName` is available

### Excluded

- `-encode` and `-encodehex` without decoding;
- `-hashfile`;
- certificate-store verification;
- command text mentioning certutil when another process is executing;
- blanket suppression by user or host.

Administrative decoding remains a possible false positive. The rule keeps those events visible and relies on case context instead of broad exclusions that could hide abuse.

## 11. Severity and Triage

The Sigma rule uses `medium`, and the Wazuh rule uses level `8`. Escalate when one or more contextual risks are present:

- unusual parent process;
- user-writable or temporary paths;
- recently downloaded or staged input;
- executable or script output;
- immediate follow-on execution;
- unexpected user, host, or time;
- related persistence, network transfer, or security-control modification.

Downgrade or close when the activity matches an approved administrative workflow, expected account, known path, maintenance window, and change record, with no suspicious follow-on behavior.

## 12. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection relationship |
|---|---|---|---|
| Stealth *(project theme: Defense Evasion)* | Deobfuscate/Decode Files or Information | [`T1140`](https://attack.mitre.org/techniques/T1140/) | Detects a trusted Windows utility using file-decoding arguments |

ATT&CK documents `certutil` as a utility that can decode Base64 content. The mapping describes the behavior and does not determine whether a matching event is malicious.

## 13. Wazuh Deployment Validation

On an installed Wazuh manager:

1. Confirm Sysmon Event `1` arrives with `win.eventdata.image` and `win.eventdata.commandLine`.
2. Confirm built-in parent rule `61603` applies to the installed version.
3. Copy the custom rule under `/var/ossec/etc/rules/`.
4. Test a representative one-line Sysmon event with `/var/ossec/bin/wazuh-logtest`.
5. Confirm rule `100201`, level `8`, and the expected decoder in the test output.
6. Restart the Wazuh manager only after the rule passes `wazuh-logtest`.
7. Run the harmless Case 11 decode exercise.
8. Verify the resulting alert fields, ATT&CK mapping, severity, and analyst context.
9. Test approved administrative counterexamples before adding exclusions.

## 14. Constraints and Limitations

- The offline validator tests the repository artifacts and shared matching logic; it does not execute the Wazuh analysis engine or a Sigma backend.
- The Wazuh parent rule and decoded field names must be confirmed against the installed version.
- The fixtures are controlled test records, not exported endpoint events.
- The test set does not measure alert latency, event loss, ingestion performance, or real-world false-positive rate.
- A renamed binary is covered by the Sigma `OriginalFileName` option but not by the current Wazuh image-path rule.
- Correlation with file creation or follow-on execution is triage guidance for this version and is not implemented as a multi-event rule.

## 15. Analyst Verdict

- **Classification:** Validated custom detection logic within the documented offline scope
- **Rule artifacts:** Sigma and Wazuh versions created
- **Test result:** Six of six fixtures passed
- **False positives tested:** Hashing, encoding-only, wrong-process mention, and certificate-store verification
- **ATT&CK:** `T1140`
- **Confidence:** High for fixture behavior; medium for Wazuh deployment portability
- **Conclusion:** The detection correctly identifies the tested `certutil.exe` decode behaviors and rejects the tested benign alternatives. It is ready for version-specific Wazuh deployment testing.

## 16. Evidence Index

| Artifact | Type | Evidentiary value |
|---|---|---|
| [Sigma rule](../../detections/sigma/windows/process_creation/case13_certutil_file_decode.yml) | Detection artifact | Portable rule definition |
| [Wazuh rule](../../detections/wazuh/case13_certutil_decode.xml) | Detection artifact | Platform-specific rule definition |
| [Fixtures](../../tests/case13/fixtures.jsonl) | Test data | Positive and negative input set |
| [Validator](../../tests/case13/test_case13_detection.py) | Executable test | Reproduces structural and behavioral checks |
| [Results](../../tests/case13/results.json) | Machine-readable result | Records the successful six-test run |
| [01 — Detection lifecycle](../../screenshots/Case%2013%20-%20Custom%20Detection/01-case13-detection-lifecycle.png) | Generated educational diagram | Explains the engineering workflow and validation boundary |
| [02 — Rule logic](../../screenshots/Case%2013%20-%20Custom%20Detection/02-case13-rule-logic.png) | Generated educational diagram | Explains the exact match decision |
| [03 — Test results](../../screenshots/Case%2013%20-%20Custom%20Detection/03-case13-test-results.png) | Generated results visualization | Summarizes the stored machine-readable test outcome |

## 17. References

- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma Windows process-creation log source](https://sigmahq.io/docs/basics/log-sources.html)
- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wazuh rule and decoder testing](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Wazuh `wazuh-logtest`](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
- [MITRE ATT&CK — Deobfuscate/Decode Files or Information, T1140](https://attack.mitre.org/techniques/T1140/)
- [MITRE ATT&CK — certutil, S0160](https://attack.mitre.org/software/S0160/)

## Case Closure

**Case 13 — Custom Detection Engineering is closed with successful offline validation.** The repository now contains a Sigma rule, Wazuh rule `100201`, six controlled fixtures, an executable validator, and a passing machine-readable result. The tested logic produced two expected matches and four expected non-matches with no errors. The detection is ready for Wazuh-version field confirmation, `wazuh-logtest`, and deployed alert review when that runtime is available.
