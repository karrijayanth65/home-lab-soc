# Case 12 — Detection Gap Investigation

> **Case type:** Detection coverage and visibility-gap analysis<br>
> **Detection:** Windows Security, Sysmon, PowerShell Operational, and Wazuh<br>
> **Severity:** Medium when the behavior is unexpected and no alert is generated<br>
> **Status:** Closed — documented gap hypothesis and validation plan<br>
> **Environment:** Isolated Windows home-lab design<br>
> **Case event time:** Not available<br>
> **Documentation and closure date:** 12 October 2026 (IST)<br>
> **Evidence mode:** Illustrative documentation<br>
> **Confidence:** Medium for the coverage analysis; low for environment-specific conclusions

> [!NOTE]
> This case investigates a potential detection gap derived from the Case 11 `certutil.exe` scenario. The available repository does not contain the endpoint events, Wazuh documents, agent configuration, or rule output needed to confirm which layer failed. The gap is therefore expressed as a testable hypothesis rather than a confirmed missed alert.

## Executive Summary

Case 12 follows the Case 11 living-off-the-land scenario through the complete detection pipeline: behavior, telemetry generation, collection, parsing, detection logic, and alerting. The review found that an analyst could miss the context of `certutil.exe -decode` if process command-line auditing is disabled, Sysmon or PowerShell channels are not forwarded, relevant fields are not searchable, or no behavioral analytic evaluates the event chain. No preserved data proves which condition existed in the previous lab, so the case records a layered gap hypothesis and an evidence-based validation plan. The case is closed as a detection-gap analysis, and its requirements become the input for Case 13 custom detection engineering.

## 1. Objective and Scope

The objective is to identify where visibility can break between a known endpoint behavior and an actionable SOC alert.

The investigation asks:

1. Did the activity generate telemetry on the endpoint?
2. Did the Wazuh agent collect the required channels?
3. Did Wazuh parse the fields needed for analysis?
4. Did detection content evaluate the behavior?
5. Was an alert generated with useful context and severity?
6. Can the result be reproduced and measured?

The scope is limited to the harmless Case 11 workflow on `WIN11-LAB`: PowerShell starts `certutil.exe` to encode and decode an inert text file. No malware, executable payload, external transfer, persistence, or unauthorized activity is included.

## 2. Detection Pipeline

![Case 12 detection pipeline](../../screenshots/Case%2012%20-%20Detection%20Gap/01-case12-detection-pipeline.png)

A detection can fail before a rule is evaluated. Each layer must pass useful context to the next:

```text
Known behavior
    ↓
Endpoint telemetry generated
    ↓
Required channels collected
    ↓
Events parsed into searchable fields
    ↓
Detection logic evaluates the behavior
    ↓
Alert contains enough context for triage
    ↓
Analyst reaches a supported verdict
```

## 3. Environment and Entities

| Entity | Case value | Relevance |
|---|---|---|
| Endpoint | Windows 11 / `WIN11-LAB` — `192.168.56.105` | Expected source of endpoint telemetry |
| Planned identity | `LAB\soc-test` | Authorized test identity from the preceding case design |
| Parent process | `powershell.exe` | Provides script and process ancestry context |
| Observed-behavior target | `certutil.exe` with encode/decode arguments | Trusted utility whose intent depends on context |
| Files | `message.txt`, `message.b64`, `decoded.txt` | Inert artifacts used to exercise file-transformation visibility |
| Wazuh endpoint | Agent `002` | Expected collector identity from the project topology |
| SOC platform | Wazuh Manager, Indexer, and Dashboard | Collection, normalization, search, and alerting path |
| Original raw evidence | Not available | Prevents confirmation of the exact failure point |

## 4. Expected Telemetry

| Source | Expected record | Required context | Dependency |
|---|---|---|---|
| Windows Security | Event ID `4688` | New process, creator process, user, and command line | Audit Process Creation; separate command-line policy for arguments |
| Sysmon | Event ID `1` | Image, command line, parent image, Process GUID, user, and configured hashes | Sysmon installed with a matching Process Create configuration |
| Sysmon | Event ID `11` | Target filename and process context for created or overwritten files | Sysmon File Create coverage and filters |
| PowerShell Operational | Event ID `4104` | Script-block content for the controlled workflow | Script-block logging enabled |
| Wazuh | Parsed Windows event-channel document | Agent, host, event ID, image, command line, parent, user, and file fields | Channel collection, decoding, indexing, and retention |
| Wazuh detection | Case-specific alert | Rule match, severity, technique, and sufficient triage context | Suitable rule or correlation logic |

Microsoft documents that the command-line field in Security Event `4688` is empty by default unless the command-line process-auditing policy is enabled. Sysmon Event `1` provides detailed process information, while Event `11` records file creation when selected by the Sysmon configuration. Wazuh monitors Windows Security by default and requires explicit `eventchannel` configuration for additional channels such as Sysmon and PowerShell Operational.

## 5. Gap Hypothesis

![Case 12 gap hypothesis](../../screenshots/Case%2012%20-%20Detection%20Gap/02-case12-gap-hypothesis.png)

The repository supports four potential gaps, but none can be marked confirmed without live evidence.

| Gap layer | Testable hypothesis | Consequence | Evidence required |
|---|---|---|---|
| Generation | Security `4688` exists but its command-line field is empty | `certutil.exe` may be visible without `-decode` context | Local Security event plus effective audit policy |
| Endpoint coverage | Sysmon Event `1` or `11` is not generated | Parent, command, hash, or file-creation context is absent | Sysmon configuration and local Sysmon events |
| Collection | Sysmon or PowerShell Operational events exist locally but are not forwarded | Endpoint has evidence that Wazuh cannot search | Agent configuration, local event, and Wazuh search result |
| Detection content | Events are collected and parsed but no analytic matches the sequence | Behavior remains a raw event without an alert | Parsed Wazuh document, rule inventory, and test result |

### Primary finding

The confirmed portfolio-level gap is **lack of detection assurance**. The repository does not contain the artifacts needed to demonstrate that the complete Case 11 behavior was generated, collected, parsed, detected, and reviewed.

### Potential false-negative path

```text
certutil.exe executes
    ↓
Process event contains little or no argument context
    ↓
File activity is absent or not forwarded
    ↓
No multi-event analytic evaluates the sequence
    ↓
No actionable alert is available to the analyst
```

This path is a hypothesis. A future controlled run must determine which steps pass or fail.

## 6. Investigation Method

Validate the pipeline from the endpoint outward. Do not start by assuming the rule is the problem.

### Step 1 — Prove generation

- Confirm effective Advanced Audit Policy settings for Process Creation.
- Confirm whether command-line capture is enabled.
- Inspect the local Security log for `4688`.
- Inspect the local Sysmon Operational log for Events `1` and `11`.
- Inspect the local PowerShell Operational log for `4104`.

### Step 2 — Prove collection

- Confirm Wazuh Agent `002` is connected and reporting.
- Review the agent configuration for Security, Sysmon, and PowerShell Operational channels.
- Compare a local event with the corresponding Wazuh document.
- Record event time, ingestion time, agent, channel, provider, and event ID.

### Step 3 — Prove parsing and searchability

- Verify process image, command line, parent process, user, host, and target filename fields are searchable.
- Record the exact Wazuh field names used by the installed version.
- Check whether XML queries or local filters discard any required events.
- Confirm retention and time-zone handling cover the validation window.

### Step 4 — Prove detection

- Inventory existing Wazuh and custom rules that evaluate `certutil.exe` or file decoding.
- Run the harmless Case 11 sequence.
- Record whether a rule matches and whether an alert is produced.
- Confirm the alert contains enough context to distinguish expected administration from a suspicious chain.

## 7. Collection Requirements

Wazuh documents `eventchannel` collection for additional Windows channels. The replacement lab should verify equivalent entries such as:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

The exact configuration must be reviewed against the installed Wazuh version and any centralized agent configuration. The Windows Security channel is collected by default, but its audit policies still determine which Security events and fields exist.

## 8. Required Search Fields

The future validation should confirm that the installed Wazuh version exposes equivalent searchable fields for:

| Category | Required values |
|---|---|
| Agent | Agent ID, agent name, and endpoint hostname |
| Event | Provider, channel, event ID, event time, and ingestion time |
| Process | Image, command line, process ID or GUID, parent image, and parent ID or GUID |
| Identity | User, domain, logon identifier, and integrity level when available |
| File | Target filename, directory, extension, and hash when available |
| Detection | Rule ID, description, level, groups, and ATT&CK mapping |

Field names vary by source and Wazuh version. Capture the actual JSON document rather than assuming a schema from an example.

## 9. Coverage Decision Matrix

| Layer | Pass criterion | Failure classification | Current result |
|---|---|---|---|
| Behavior | Harmless Case 11 activity completes | Test execution issue | Not tested |
| Generation | Required local events and fields exist | Telemetry-generation gap | Unknown |
| Collection | Local events appear in Wazuh | Collection or filtering gap | Unknown |
| Parsing | Required fields are normalized and searchable | Decoder or mapping gap | Unknown |
| Detection | Logic matches the intended behavior | Detection-content gap | No case-specific result available |
| Alerting | Alert is created with useful severity and context | Alerting or enrichment gap | Unknown |
| Triage | Analyst can reach a supported verdict | Investigation-context gap | Model defined; live result pending |

## 10. Analysis and Findings

### Finding 1 — Visibility must be measured at every layer

An absent alert does not prove that the behavior did not occur. It can indicate missing telemetry, missing collection, parsing failure, unsuitable logic, suppression, or an alerting problem.

### Finding 2 — `4688` alone may lack decisive context

If command-line capture is disabled, `4688` can show `certutil.exe` process creation without the arguments needed to identify encoding or decoding behavior.

### Finding 3 — Additional channels require deliberate collection

Sysmon and PowerShell Operational can provide richer context, but they must be enabled on the endpoint and included in Wazuh collection.

### Finding 4 — Raw visibility and detection are separate outcomes

Searchable events prove visibility. A detection requires logic that evaluates those events, applies context, and produces an alert that an analyst can use.

### Finding 5 — The next case has concrete inputs

Case 13 should implement and test detection logic only after the required process, command-line, file, identity, and timing fields are confirmed.

## 11. MITRE ATT&CK Context

| Tactic | Technique | ID | Relevance | Evidence status |
|---|---|---|---|---|
| Stealth *(project theme: Defense Evasion)* | Deobfuscate/Decode Files or Information | [`T1140`](https://attack.mitre.org/techniques/T1140/) | The Case 11 behavior uses the same trusted-utility decoding pattern that the gap analysis must cover | Behavioral model; no captured case event |
| Execution | PowerShell | [`T1059.001`](https://attack.mitre.org/techniques/T1059/001/) | PowerShell supplies the planned parent and script context | Behavioral model; no captured script-block event |

ATT&CK describes the behavior to cover; it does not prove that a specific alert or malicious event occurred.

## 12. Constraints and Limitations

- No original Case 12 endpoint event, Wazuh document, alert, agent configuration, or rule output is available.
- The effective Windows audit policy, Sysmon configuration, PowerShell logging policy, and Wazuh channel configuration are unknown.
- No event time, ingestion time, process identifiers, hashes, rule IDs, document IDs, or alert severity can be verified.
- The diagrams represent the investigation method and target state.
- The analysis cannot measure event loss, ingestion delay, false-positive rate, false-negative rate, or rule performance.
- A live controlled run is required to classify any environment-specific gap as confirmed.

## 13. Analyst Verdict

- **Classification:** Potential false negative / detection-assurance gap
- **Authorization:** Authorized lab design
- **Scope:** One Windows endpoint, one trusted utility scenario, and the Windows-to-Wazuh pipeline
- **Confirmed issue:** The repository lacks end-to-end evidence demonstrating detection coverage
- **Environment-specific root cause:** Inconclusive; telemetry, collection, parsing, and detection hypotheses remain to be tested
- **Confidence:** Medium for the coverage model; low for the exact historical failure point
- **Conclusion:** The detection path cannot be considered validated until the replacement lab proves that the Case 11 behavior is generated, collected, parsed, searchable, detected, and reviewable.

## 14. Remediation and Validation Plan

![Case 12 remediation loop](../../screenshots/Case%2012%20-%20Detection%20Gap/03-case12-remediation-loop.png)

1. Enable and verify process creation, command-line, PowerShell, and Sysmon telemetry.
2. Configure Wazuh collection for every required channel.
3. Run the harmless Case 11 text-file exercise.
4. Compare endpoint events with Wazuh documents.
5. Record which fields are generated, collected, parsed, and searchable.
6. Measure each failed layer separately.
7. Use the confirmed fields to build the Case 13 detection.
8. Test both the intended match and approved administrative counterexamples.
9. Retest after every configuration, parser, filter, or rule change.

### Handoff requirements for Case 13

Case 13 should not begin rule implementation until it has:

- a captured process event with the `certutil.exe` image and full arguments;
- parent process and user context;
- file-creation context for the decoded output where available;
- confirmed Wazuh field names;
- at least one expected positive test and one benign comparison;
- a defined severity, suppression strategy, and analyst triage fields.

## 15. Evidence Index

| Artifact | Type | Purpose |
|---|---|---|
| [01 — Detection pipeline](../../screenshots/Case%2012%20-%20Detection%20Gap/01-case12-detection-pipeline.png) | Generated educational diagram | Shows every layer from behavior to potential false negative |
| [02 — Gap hypothesis](../../screenshots/Case%2012%20-%20Detection%20Gap/02-case12-gap-hypothesis.png) | Generated educational diagram | Separates unknown current coverage from the required target state |
| [03 — Remediation loop](../../screenshots/Case%2012%20-%20Detection%20Gap/03-case12-remediation-loop.png) | Generated educational diagram | Defines the evidence-driven validation cycle and Case 13 handoff |

## 16. References

- [MITRE ATT&CK — Deobfuscate/Decode Files or Information, T1140](https://attack.mitre.org/techniques/T1140/)
- [MITRE ATT&CK — PowerShell, T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft — Event 4688: A new process has been created](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)
- [Microsoft — Command-line process auditing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- [Microsoft Sysinternals — Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Microsoft — Sysmon events](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/sysmon-events)
- [Wazuh — Configuring Windows event-channel collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html)
- [Wazuh — Local file and event-channel configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)

## Case Closure

**Case 12 — Detection Gap Investigation is closed as a documented coverage analysis and validation plan.** The case traces the Case 11 `certutil.exe` behavior through telemetry generation, Wazuh collection, parsing, detection content, alerting, and analyst review. It confirms a portfolio-level detection-assurance gap while leaving the historical technical failure point inconclusive. The defined telemetry, field, test, and tuning requirements are ready to guide Case 13 custom detection engineering.
