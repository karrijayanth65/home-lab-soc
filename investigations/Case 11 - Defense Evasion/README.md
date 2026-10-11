# Case 11 — Defense Evasion / Living-off-the-Land Concepts

> **Case type:** Authorized living-off-the-land behavior analysis<br>
> **Detection:** Windows Security, Sysmon, PowerShell Operational, and Wazuh<br>
> **Severity:** Informational for this authorized exercise; medium to high when unexpected<br>
> **Status:** Closed — documentation proof of concept; live validation pending<br>
> **Environment:** Isolated Windows home-lab design<br>
> **Case event time:** Not available<br>
> **Documentation and closure date:** 12 October 2026 (IST)<br>
> **Evidence mode:** Illustrative documentation<br>
> **Confidence:** Medium for the detection model; low for event-specific validation

> [!NOTE]
> The supporting visuals explain the planned investigation and correlation flow. They are educational illustrations rather than exported Windows or Wazuh records. A rebuilt lab must supply the event-specific fields before the detection can be measured.

## Executive Summary

Case 11 examines how a legitimate Windows utility can become suspicious when its command-line arguments and surrounding activity resemble defense-evasion behavior. The safe lab design uses `certutil.exe` to encode and decode an inert text file on `WIN11-LAB`, then correlates the process ancestry, command line, file creation, user, host, and sequence in Wazuh. The technique is mapped to MITRE ATT&CK `T1140` because adversaries can use trusted utilities to decode staged content, while the exercise itself remains authorized and harmless. The case is closed as a documented detection model; live telemetry validation remains pending because event records from the lab are unavailable.

## 1. Objective and Scope

The objective is to show why binary reputation alone cannot determine intent. The investigation asks whether `certutil.exe` activity is expected administration or a suspicious decoding chain that requires escalation.

The case covers:

- a harmless local file encode/decode sequence;
- parent and child process context;
- command-line and file-creation telemetry;
- Windows Security, Sysmon, PowerShell, and Wazuh correlation;
- behavioral detection logic and false-positive controls;
- evidence requirements for future live validation.

The case does not include malware, executable payloads, persistence, privilege escalation, credential access, external downloads, or unauthorized access.

## 2. Environment and Evidence Flow

| Component | Case value | Role |
|---|---|---|
| Endpoint | Windows 11 / `WIN11-LAB` — `192.168.56.105` | Runs the authorized exercise and generates endpoint telemetry |
| Planned identity | `LAB\soc-test` | Dedicated test account inherited from the preceding case design |
| Parent process | `powershell.exe` | Creates the inert input and starts the trusted utility |
| Utility | `C:\Windows\System32\certutil.exe` | Encodes and decodes the harmless text file |
| Files | `message.txt`, `message.b64`, `decoded.txt` | Inert artifacts used to exercise the telemetry path |
| Wazuh endpoint | Agent `002` | Collects configured Windows event channels |
| SOC platform | Wazuh Manager, Indexer, and Dashboard | Supports search, correlation, and analyst review |
| Network | Isolated host-only network `192.168.56.0/24` | Laboratory boundary; no external download is required |

![Case 11 evidence flow](../../screenshots/Case%2011%20-%20Defense%20Evasion/01-case11-evidence-flow.png)

The diagram defines the expected collection path from the controlled activity to analyst review.

## 3. Safe Activity Design

The planned exercise uses only text content. It verifies that the decoded file matches the original and does not execute the result.

```powershell
$casePath = Join-Path $env:TEMP 'case11-lab'
New-Item -ItemType Directory -Path $casePath -Force | Out-Null
Set-Content -Path (Join-Path $casePath 'message.txt') -Value 'SOC lab validation'

certutil.exe -encode `
  (Join-Path $casePath 'message.txt') `
  (Join-Path $casePath 'message.b64')

certutil.exe -decode `
  (Join-Path $casePath 'message.b64') `
  (Join-Path $casePath 'decoded.txt')

Get-FileHash (Join-Path $casePath 'message.txt') -Algorithm SHA256
Get-FileHash (Join-Path $casePath 'decoded.txt') -Algorithm SHA256
```

![Case 11 safe activity flow](../../screenshots/Case%2011%20-%20Defense%20Evasion/02-case11-safe-activity-flow.png)

Matching hashes would confirm content integrity. The hashes themselves must be captured from the future lab run and are therefore recorded as `Not available` in this case.

## 4. Detection Details

| Attribute | Expected value |
|---|---|
| Windows process event | Security Event ID `4688`, when Audit Process Creation is enabled |
| Windows command line | Available in `4688` only when **Include command line in process creation events** is enabled |
| Sysmon process event | Event ID `1`, including image, command line, parent process, Process GUID, and configured hashes |
| Sysmon file event | Event ID `11`, when the Sysmon configuration records the relevant file creation |
| PowerShell event | Event ID `4104`, when script-block logging is enabled |
| Wazuh source | `Security`, `Microsoft-Windows-Sysmon/Operational`, and `Microsoft-Windows-PowerShell/Operational` as configured |
| Wazuh agent | `002` expected from the repository topology |
| Alert or rule ID | Not available; no case-specific Wazuh alert has been captured |
| Detection focus | `certutil.exe` with encode/decode arguments, its parent, file paths, user, host, time sequence, and follow-on execution |

Microsoft documents `4688` as a process-creation event and notes that command-line capture requires a separate policy. Sysmon Event `1` provides process context and Event `11` records file creation when the active Sysmon configuration includes it. Wazuh can collect additional Windows event channels using `eventchannel` entries in the Windows agent configuration.

## 5. Entities and Key Attributes

| Entity | Value | Investigative relevance |
|---|---|---|
| Host | `WIN11-LAB` | Establishes the affected endpoint and its expected role |
| User | `LAB\soc-test` | Planned authorized identity; live event value not yet captured |
| Parent image | `powershell.exe` | Establishes how the utility was launched |
| Child image | `certutil.exe` | Legitimate binary requiring behavioral context |
| Command arguments | `-encode` and `-decode` | High-value fields for distinguishing routine certificate use from file transformation |
| Input | `message.txt` | Harmless source text |
| Encoded artifact | `message.b64` | Staged Base64 representation |
| Decoded output | `decoded.txt` | Harmless recovered text |
| File hashes | Not available | Must be captured during live validation |
| Process IDs / GUIDs | Not available | Needed to correlate exact process events in the rebuilt lab |
| Wazuh document IDs | Not available | Needed to prove ingestion and alert behavior |

## 6. Investigation Timeline

| Sequence | Activity | Expected evidence | Validation state |
|---|---|---|---|
| 1 | PowerShell creates the case directory and `message.txt` | PowerShell `4104`; optional Sysmon file event | Documentation only |
| 2 | PowerShell starts `certutil.exe -encode` | Security `4688` and Sysmon `1` | Documentation only |
| 3 | `message.b64` is created | Sysmon `11` when configured | Documentation only |
| 4 | PowerShell starts `certutil.exe -decode` | Security `4688` and Sysmon `1` | Documentation only |
| 5 | `decoded.txt` is created | Sysmon `11` when configured | Documentation only |
| 6 | SHA-256 values are compared | PowerShell `4104` plus command output retained by the analyst | Documentation only |
| 7 | Wazuh collects and indexes the configured channels | Agent, host, event, process, and command-line fields | Not available |
| 8 | Analyst reviews context and follow-on activity | Correlated event sequence and case verdict | Detection model complete |

## 7. Behavioral Correlation

![Case 11 behavioral correlation](../../screenshots/Case%2011%20-%20Defense%20Evasion/03-case11-behavioral-correlation.png)

The investigation should correlate six dimensions before reaching a verdict:

1. **Parent process:** Was `certutil.exe` launched by an expected administrative process or by a script, Office application, service, or unusual ancestor?
2. **Command-line arguments:** Does the command encode, decode, or retrieve content? Are the input and output paths expected?
3. **File creation:** What was written, where was it written, and what type of content resulted?
4. **User and host:** Is the identity authorized to perform this work on this endpoint?
5. **Time sequence:** Did file staging immediately precede decoding, and did another process execute the output?
6. **Follow-on execution:** Was the decoded artifact executed, persisted, or transferred?

The trusted Microsoft path and signature of `certutil.exe` establish binary identity. They do not establish benign intent.

## 8. Detection Logic

A useful analytic starts with process creation for `certutil.exe` and an encode/decode argument, then increases confidence when the surrounding chain is unusual.

```text
Process image ends with \certutil.exe
AND command line contains -decode, -decodehex, -encode, or -encodehex
AND one or more contextual risks exist:
    unusual parent process
    user-writable input or output path
    recently staged input
    newly created output
    follow-on execution
    unexpected user, host, or time
```

### False-positive controls

- approved certificate administration and PKI workflows;
- software deployment or support tooling that uses `certutil.exe`;
- known automation accounts, management hosts, paths, and maintenance windows;
- commands that query certificate stores without transforming files;
- repeatable baselines supported by change or service records.

Avoid suppressing all activity from a trusted binary. Tune on the complete administrative pattern and continue to retain high-risk argument combinations and follow-on execution.

## 9. Findings

### Finding 1 — Reputation is only one data point

`certutil.exe` is a legitimate Microsoft utility. Its trusted location or signature cannot determine whether a particular use is authorized.

### Finding 2 — Command-line visibility is essential

A process event containing only the image name cannot distinguish certificate administration from file decoding. Security `4688` command-line policy or Sysmon process telemetry is required for this distinction.

### Finding 3 — Sequence raises confidence

The strongest analytic connects file staging, decoding, output creation, and follow-on execution. This is more precise than alerting on every `certutil.exe` launch.

### Finding 4 — Collection must be configured before testing

Security auditing, command-line capture, PowerShell logging, Sysmon coverage, and Wazuh event-channel collection must be verified before the activity occurs.

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Reason for mapping | Evidence status |
|---|---|---|---|---|
| Stealth *(project theme: Defense Evasion)* | Deobfuscate/Decode Files or Information | [`T1140`](https://attack.mitre.org/techniques/T1140/) | ATT&CK documents the use of built-in utilities such as `certutil.exe` to decode staged content | Behavioral model; no captured case event |
| Execution | PowerShell | [`T1059.001`](https://attack.mitre.org/techniques/T1059/001/) | PowerShell provides the parent scripting context for the planned exercise | Behavioral model; no captured script-block event |

The current ATT&CK page places `T1140` under the **Stealth** tactic. The repository retains its planned **Defense Evasion** case name. The mapping describes behavior and does not imply that the authorized exercise is malicious.

## 11. Constraints and Limitations

- No original Case 11 Security, Sysmon, PowerShell, or Wazuh events are available.
- The event time, ingestion time, process IDs, Process GUIDs, hashes, Wazuh rule ID, and Wazuh document IDs are unknown.
- Sysmon Event `11` depends on the active Sysmon configuration and filtering rules.
- Security `4688` command-line data depends on audit-policy configuration and may expose sensitive arguments.
- PowerShell `4104` depends on script-block logging.
- The current package demonstrates investigation logic, not rule performance, false-positive rate, or successful alert generation.

## 12. Analyst Verdict

- **Classification:** Authorized illustrative lab scenario; event-specific result inconclusive
- **Authorization:** Authorized by design
- **Scope:** One Windows endpoint, one planned test identity, one trusted binary, and inert text artifacts
- **Impact:** None in the documented scenario
- **Confidence:** Medium for the detection model; low for historical event validation
- **Conclusion:** `certutil.exe` encode/decode activity requires contextual investigation. The planned behavior is benign, while the same utility and arguments combined with suspicious staging or follow-on execution would justify escalation.

## 13. Response and Recommendations

No containment or eradication action is required for the documented authorized exercise.

For the future live validation:

1. Confirm Audit Process Creation and command-line capture before testing.
2. Install and validate a Sysmon configuration that records Process Create and relevant File Create events.
3. Enable PowerShell script-block logging in the isolated lab.
4. Configure Wazuh to collect Sysmon and PowerShell Operational channels.
5. Record the baseline before running the exercise.
6. Execute only the inert text workflow shown in this case.
7. Export the raw events and retain process identifiers, hashes, and Wazuh document IDs.
8. Test the detection against approved administrative use before tuning exclusions.
9. Escalate when decoding is followed by execution, persistence, external transfer, or activity outside the approved baseline.

## 14. Evidence Index

| Artifact | Type | Purpose |
|---|---|---|
| [01 — Evidence flow](../../screenshots/Case%2011%20-%20Defense%20Evasion/01-case11-evidence-flow.png) | Generated educational diagram | Defines the system and telemetry flow |
| [02 — Safe activity flow](../../screenshots/Case%2011%20-%20Defense%20Evasion/02-case11-safe-activity-flow.png) | Generated educational diagram | Shows the inert encode/decode workflow and integrity check |
| [03 — Behavioral correlation](../../screenshots/Case%2011%20-%20Defense%20Evasion/03-case11-behavioral-correlation.png) | Generated educational diagram | Shows the evidence dimensions needed for an analyst verdict |

## 15. References

- [MITRE ATT&CK — Deobfuscate/Decode Files or Information, T1140](https://attack.mitre.org/techniques/T1140/)
- [MITRE ATT&CK — certutil, S0160](https://attack.mitre.org/software/S0160/)
- [MITRE ATT&CK — PowerShell, T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft — Event 4688: A new process has been created](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)
- [Microsoft — Command-line process auditing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- [Microsoft Sysinternals — Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Microsoft — Sysmon events](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/sysmon-events)
- [Wazuh — Configuring Windows event-channel collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html)

## Case Closure

**Case 11 — Defense Evasion / Living-off-the-Land Concepts is closed as a documentation proof of concept.** The case defines a safe `certutil.exe` encode/decode exercise on `WIN11-LAB`, the Windows and Wazuh evidence required to investigate it, the behavioral factors that separate expected administration from a suspicious chain, and the related ATT&CK mappings. The detection model is complete with medium confidence; event-specific validation remains pending until the isolated lab is rebuilt and raw telemetry is captured.
