# Case 14 — Multi-Stage Attack Chain

> **Case type:** Advanced investigation and temporal correlation<br>
> **Detection sources:** Windows Security and Sysmon process creation<br>
> **Severity:** High when the complete ordered chain matches<br>
> **Status:** Closed — correlation artifact created and offline validation passed<br>
> **Environment:** Repository-based attack-chain validation for `WIN11-LAB`<br>
> **Validation date:** 12 October 2026 (IST)<br>
> **Evidence mode:** Executed offline correlation tests using controlled timelines and supporting diagrams<br>
> **Confidence:** High for the tested correlation behavior; medium for production portability

> [!NOTE]
> The repository test suite executed the correlation logic against six controlled scenarios and passed all six. This proves the stored ordering, identity, scope, and time-window logic for those inputs. Deployment against collected Windows and Wazuh events remains environment-dependent.

## Executive Summary

Case 14 joins five individually understandable signals into one higher-confidence investigation: a successful network logon, a WinRM provider process, PowerShell launched through WinRM, `certutil.exe` decoding a file, and scheduled-task creation. The correlation requires the same host and user, the documented order, and a maximum span of 30 minutes. The positive timeline matched all five stages in seven minutes. Five negative scenarios were rejected because they omitted a stage, crossed hosts, crossed users, exceeded the time window, or presented the events out of order.

The result demonstrates why isolated events need context. A network logon, PowerShell command, decoder, or scheduled task may each be legitimate. Their ordered combination on one endpoint and account warrants high-priority review. The case closes with a platform-neutral correlation specification, controlled test scenarios, an executable validator, machine-readable results, investigation guidance, and ATT&CK mappings.

## 1. Objective and Scope

The objective is to determine whether related Windows events form a coherent remote-access and persistence chain rather than unrelated administrative activity.

The tested chain is:

```text
Network logon
    ↓
WinRM session
    ↓
PowerShell execution
    ↓
certutil file decode
    ↓
Scheduled-task creation
```

The scope includes:

- Windows Security Event `4624` with Logon Type `3`;
- Sysmon Event `1` for process creation;
- ordered temporal correlation by host and user;
- a 30-minute maximum span;
- six positive and negative timeline scenarios;
- ATT&CK mapping, triage, scope, and response guidance.

The case does not determine malicious intent from one event. It raises the priority of the combined behavior and preserves the context an analyst needs to validate authorization.

## 2. Environment and Evidence Flow

| Entity | Value | Role |
|---|---|---|
| Source address | `192.168.56.20` | Controlled remote administration source in the positive fixture |
| Target host | `WIN11-LAB` | Windows endpoint where the chain is evaluated |
| Account | `lab-admin` | Account joining the positive sequence |
| Security channel | Windows Security | Supplies successful network-logon context |
| Endpoint channel | Microsoft-Windows-Sysmon/Operational | Supplies process image, command line, and ancestry |
| Correlation key | `host` + `user` | Prevents unrelated entities from being joined |
| Correlation window | 30 minutes | Limits temporal distance between the first and final stages |

![Case 14 evidence flow](../../screenshots/Case%2014%20-%20Multi-Stage%20Attack%20Chain/01-case14-evidence-flow.png)

```text
Windows Security 4624 ─┐
                       ├─ Normalize host, user, time, process, and command
Sysmon Event 1 ────────┘
                                   ↓
                      Ordered 30-minute correlation
                                   ↓
                         High-priority case review
```

## 3. Correlation Details

The correlation specification is stored at [`detections/correlation/case14_multi_stage_attack_chain.yml`](../../detections/correlation/case14_multi_stage_attack_chain.yml).

| Stage | Required evidence | Match condition |
|---|---|---|
| Network logon | Windows Security `4624` | `LogonType = 3` |
| WinRM session | Sysmon `1` | Image ends with `wsmprovhost.exe` |
| PowerShell execution | Sysmon `1` | PowerShell image with `wsmprovhost.exe` as parent |
| File decode | Sysmon `1` | `certutil.exe` with `-decode` or `-decodehex` |
| Scheduled-task creation | Sysmon `1` | `schtasks.exe` with `/Create` |

All stages must:

1. occur in the documented order;
2. share the same normalized host;
3. share the same normalized user; and
4. complete within 1,800 seconds.

The specification is platform-neutral. A production implementation must translate its field names and sequence behavior into the target SIEM while preserving these invariants.

## 4. Entities and Key Attributes

| Attribute | Positive fixture value | Investigative use |
|---|---|---|
| Host | `WIN11-LAB` | Defines the affected endpoint |
| User | `lab-admin` | Links authentication and execution context |
| Source IP | `192.168.56.20` | Identifies the origin of the network logon |
| Initial event | Security `4624`, Logon Type `3` | Establishes remote authentication |
| Remote host process | `wsmprovhost.exe` | Supports WinRM session context |
| Script interpreter | `powershell.exe` | Establishes command execution through WinRM |
| Decode utility | `certutil.exe` | Identifies file-decoding behavior |
| Persistence utility | `schtasks.exe` | Identifies scheduled-task creation behavior |
| Task name | `SOC-Lab-HealthCheck` | Controlled fixture task identifier |
| Process IDs | Not available | Not needed by this fixture validator |
| Process GUIDs | Not available | Recommended for live process-chain confirmation |
| File hash | Not available | Must be collected when validating decoded content |

## 5. Ordered Activity Timeline

The positive controlled timeline contains the following records:

| Time (UTC) | Source | Activity | Correlation value |
|---|---|---|---|
| 10:00:00 | Windows Security | Network logon to `WIN11-LAB` by `lab-admin` from `192.168.56.20` | Establishes remote entry context |
| 10:01:00 | Sysmon | `wsmprovhost.exe` starts | Supports WinRM session |
| 10:02:00 | Sysmon | PowerShell starts beneath `wsmprovhost.exe` | Links remote session to execution |
| 10:04:00 | Sysmon | `certutil.exe -decode` runs | Adds file-decoding behavior |
| 10:07:00 | Sysmon | `schtasks.exe /Create` runs | Adds persistence-related behavior |

The full chain spans 420 seconds. Each timestamp belongs to controlled test data and exists to exercise the correlation window.

![Case 14 ordered timeline](../../screenshots/Case%2014%20-%20Multi-Stage%20Attack%20Chain/02-case14-ordered-timeline.png)

## 6. Test Design

The scenarios are stored at [`tests/case14/scenarios.json`](../../tests/case14/scenarios.json).

| Scenario | Expected | Purpose |
|---|---|---|
| `complete_chain_same_host_user` | Correlate | Confirms all five ordered stages within seven minutes |
| `missing_decode_stage` | Reject | Prevents incomplete chains from alerting |
| `different_host_breaks_chain` | Reject | Prevents cross-host event stitching |
| `different_user_breaks_chain` | Reject | Prevents cross-account event stitching |
| `outside_thirty_minute_window` | Reject | Enforces the maximum temporal span |
| `out_of_order_activity` | Reject | Enforces stage order |

These counterexamples are material controls. A correlation rule that only checks whether all event types exist could combine unrelated activity and produce a misleading incident.

## 7. Executed Validation

The executable validator is stored at [`tests/case14/test_case14_correlation.py`](../../tests/case14/test_case14_correlation.py). It reads the specification and scenarios, classifies events from their fields, groups on the first event's host and user, enforces the ordered stages, measures elapsed time, and writes a JSON report.

The validation command was:

```powershell
python tests/case14/test_case14_correlation.py `
  --spec detections/correlation/case14_multi_stage_attack_chain.yml `
  --scenarios tests/case14/scenarios.json `
  --output tests/case14/results.json
```

The stored [`results.json`](../../tests/case14/results.json) reports:

```json
{
  "validation_type": "offline ordered-temporal correlation validation",
  "passed": true,
  "artifact_errors": [],
  "tests_total": 6,
  "tests_passed": 6,
  "expected_correlations": 1,
  "actual_correlations": 1
}
```

### Validation outcome

- Correlation specification structure: passed
- Specification UUID: valid
- Required ordering and grouping fields: present
- Required ATT&CK tags: present
- Timeline scenarios executed: `6`
- Scenarios passed: `6/6`
- Expected complete correlations: `1`
- Actual complete correlations: `1`
- False correlations: `0`
- Missed expected correlations: `0`

![Case 14 validation results](../../screenshots/Case%2014%20-%20Multi-Stage%20Attack%20Chain/03-case14-correlation-results.png)

## 8. Analysis and Findings

### Observations

- The complete same-host and same-user sequence matched all five stages.
- The positive sequence completed in 420 seconds, below the 1,800-second threshold.
- Removing the decode stage prevented correlation.
- Moving the decode event to another host prevented correlation.
- Assigning the decode event to another user prevented correlation.
- Extending the sequence to 2,700 seconds prevented correlation.
- Placing decode before PowerShell prevented correlation.

### Interpretation

Host, user, order, and elapsed time each contribute distinct protection against false correlation. No single event establishes an incident. The combined sequence has greater investigative value because it connects remote access to execution, decoding, and persistence-related behavior.

### Detection decision

The correlation should create a high-priority investigation when all five stages match. It should not automatically declare compromise. An analyst must still confirm account authorization, the source system, the decoded file, the scheduled-task action, endpoint role, maintenance context, and follow-on activity.

## 9. Investigation and Threat-Hunting Flow

When the chain matches, the analyst should:

1. verify the target hostname, account, source address, and authentication package;
2. confirm whether the source address is an approved administration system;
3. inspect the `wsmprovhost.exe` and PowerShell process ancestry;
4. recover the complete PowerShell and `certutil.exe` command lines;
5. identify, hash, and classify the decoded input and output files;
6. retrieve the scheduled-task XML or equivalent task definition;
7. check the task action, trigger, principal, creation actor, and execution history;
8. hunt for the same account, source address, filenames, task name, or command pattern on other hosts;
9. review network connections and child processes after the decode and task creation;
10. document whether the activity was authorized, suspicious, or confirmed malicious.

## 10. Scope Assessment

| Scope question | Required evidence |
|---|---|
| Was only `WIN11-LAB` affected? | Search all hosts for the account, source IP, commands, file paths, and task name |
| Was the account expected? | Identity owner, privilege level, maintenance record, and authentication history |
| Was the decoded file harmless? | File hash, type, signature, content analysis, and creation provenance |
| Did persistence execute? | Task operational logs, process creation, and task history |
| Did the chain create network activity? | Sysmon network events, firewall records, DNS, or proxy telemetry |
| Were other persistence methods used? | Services, run keys, startup folders, WMI subscriptions, and additional tasks |

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Relationship to this case |
|---|---|---|---|
| Lateral Movement | Windows Remote Management | [`T1021.006`](https://attack.mitre.org/techniques/T1021/006/) | Network logon and `wsmprovhost.exe` support remote-management context |
| Execution | PowerShell | [`T1059.001`](https://attack.mitre.org/techniques/T1059/001/) | PowerShell runs beneath the WinRM provider process |
| Defense Evasion | Deobfuscate/Decode Files or Information | [`T1140`](https://attack.mitre.org/techniques/T1140/) | `certutil.exe` decodes a staged file |
| Persistence / Execution | Scheduled Task | [`T1053.005`](https://attack.mitre.org/techniques/T1053/005/) | `schtasks.exe /Create` creates the persistence-related stage |

The mappings describe observable behavior. They do not prove malicious intent or actor attribution.

## 12. Severity and Triage

The complete chain is rated **high** because it combines remote access, scripting, file decoding, and persistence-related activity. Raise urgency when:

- the account or source address is unexpected;
- the target is privileged or business-critical;
- the decoded output is executable, unsigned, or newly downloaded;
- the task runs with elevated privileges or at logon/startup;
- child processes or network connections follow the decoded file;
- the same chain appears on multiple endpoints.

Downgrade only when the source, account, commands, files, task definition, target, and timing all match an approved workflow and no suspicious follow-on behavior exists.

## 13. Response and Hardening

For an unauthorized match:

1. preserve the correlated events, raw logs, task definition, process details, and file artifacts;
2. isolate the endpoint when continuing activity or material risk is present;
3. disable or reset the involved account according to incident-response policy;
4. remove the task after evidence preservation and authorization;
5. quarantine harmful files and block confirmed indicators;
6. investigate the source system and any additional targets;
7. restore approved configuration and monitor for recurrence.

Preventive improvements include limiting WinRM to managed administration sources, applying least privilege, enabling command-line and PowerShell logging, deploying Sysmon with an appropriate configuration, auditing scheduled-task creation, and retaining enough data for cross-source correlation.

## 14. Production Implementation Guidance

Before deployment in Wazuh or another SIEM:

1. confirm Security Event `4624` and Logon Type fields are collected;
2. confirm Sysmon Event `1` includes image, parent image, command line, user, and host;
3. normalize account names and hostnames consistently across sources;
4. preserve event time and ingestion time separately;
5. translate the five stage conditions into the target platform;
6. group by host and user and enforce the 30-minute ordered window;
7. test approved administration as negative or review-required cases;
8. measure event delay before selecting a production window;
9. validate the correlation with harmless authorized activity;
10. monitor match volume and tune with narrow, evidence-based exceptions.

## 15. Constraints and Visibility Gaps

- The scenarios are controlled repository fixtures, not exported endpoint events.
- The validator does not execute the Wazuh correlation engine or query a live index.
- Process IDs, Process GUIDs, Logon IDs, task XML, and file hashes are not present in the fixtures.
- Field names and parent-child relationships depend on collection and normalization quality.
- Event arrival may differ from event occurrence order in a production pipeline.
- The first-event host and user define the test correlation key; production systems should normalize aliases and account domains.
- A 30-minute threshold is a starting point and requires environment-specific tuning.

## 16. Analyst Verdict

- **Classification:** Validated multi-stage correlation logic within the documented offline scope
- **Authorization:** Controlled SOC home-lab portfolio scenario
- **Correlation result:** One complete sequence detected; five incomplete or invalid sequences rejected
- **Scope:** One Windows host and one account per valid chain
- **ATT&CK:** `T1021.006`, `T1059.001`, `T1140`, `T1053.005`
- **Confidence:** High for the tested logic; medium for target-SIEM portability
- **Conclusion:** The validator correctly joins the five required stages only when host, user, order, and time-window requirements are satisfied. The specification is ready for translation and validation in the target SIEM.

## 17. Evidence Index

| Artifact | Type | Evidentiary value |
|---|---|---|
| [Correlation specification](../../detections/correlation/case14_multi_stage_attack_chain.yml) | Detection artifact | Defines stages, grouping, order, timing, severity, and ATT&CK tags |
| [Controlled scenarios](../../tests/case14/scenarios.json) | Test data | Supplies one positive and five negative timelines |
| [Correlation validator](../../tests/case14/test_case14_correlation.py) | Executable test | Reproduces classification, grouping, ordering, and timing checks |
| [Validation results](../../tests/case14/results.json) | Machine-readable result | Records the successful six-scenario run |
| [01 — Evidence flow](../../screenshots/Case%2014%20-%20Multi-Stage%20Attack%20Chain/01-case14-evidence-flow.png) | Generated educational diagram | Explains source normalization and correlation flow |
| [02 — Ordered timeline](../../screenshots/Case%2014%20-%20Multi-Stage%20Attack%20Chain/02-case14-ordered-timeline.png) | Generated educational diagram | Shows the five-stage seven-minute sequence |
| [03 — Correlation results](../../screenshots/Case%2014%20-%20Multi-Stage%20Attack%20Chain/03-case14-correlation-results.png) | Generated results visualization | Summarizes the six executed scenarios |

## 18. References

- [Microsoft — 4624: An account was successfully logged on](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)
- [Microsoft Sysinternals — Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [MITRE ATT&CK — Windows Remote Management, T1021.006](https://attack.mitre.org/techniques/T1021/006/)
- [MITRE ATT&CK — PowerShell, T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK — Deobfuscate/Decode Files or Information, T1140](https://attack.mitre.org/techniques/T1140/)
- [MITRE ATT&CK — Scheduled Task/Job: Scheduled Task, T1053.005](https://attack.mitre.org/techniques/T1053/005/)

## Case Closure

**Case 14 — Multi-Stage Attack Chain is closed with successful offline correlation validation.** The repository now contains a five-stage correlation specification, six controlled timelines, an executable validator, a passing machine-readable result, investigation guidance, and supporting visuals. The tested logic produced one expected correlation and rejected five invalid chains without error. Case 15 — Full SOC Incident Response Capstone is the next planned investigation.
