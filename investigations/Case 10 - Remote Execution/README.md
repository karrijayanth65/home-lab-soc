# Case 10 — Remote Execution

> **Case type:** Authorized remote administration / remote execution reconstruction  
> **Detection:** Windows Security, PowerShell Operational, WinRM Operational, and Wazuh  
> **Severity:** Informational for the authorized lab narrative; potentially high when unexpected  
> **Status:** Closed — reconstructed proof of concept  
> **Environment:** Isolated home lab reconstruction  
> **Case event time:** Not available  
> **Reconstruction and closure date:** 12 October 2026 (IST)  
> **Evidence confidence:** Low for event-specific validation; medium for the documented telemetry model

> [!CAUTION]
> The original home-lab device and Case 10 evidence are no longer available. Every image in this case is a generated, visibly watermarked reconstruction created to explain the investigation flow. The images are not original screenshots, raw logs, or proof that a specific alert fired. This case is closed as a documentation reconstruction and should be revalidated when a replacement lab is available.

## Executive Summary

Case 10 reconstructs an authorized WinRM and PowerShell Remoting workflow from the Kali lab host (`192.168.56.106`) to the Windows 11 endpoint (`192.168.56.105`). The intended investigation correlates a network logon, the WinRM execution context, PowerShell activity, process creation, and Wazuh ingestion. The previous repository topology supports the identities and network roles used in this reconstruction, but no original Case 10 events, alert documents, or packet captures survived the device loss. The analyst verdict is therefore **authorized reconstructed lab activity with event-specific validation remaining inconclusive**.

## 1. Objective and Scope

The objective is to document how a SOC analyst should recognize and investigate remote command execution through Windows Remote Management without representing reconstructed material as captured evidence.

The case covers:

- an authorized connection from the controlled Kali host to the Windows lab endpoint;
- authentication and remote-session context;
- expected Windows, PowerShell, and WinRM telemetry;
- parent/child process relationships associated with remote PowerShell;
- the expected Wazuh collection and correlation path;
- investigation limitations created by loss of the original lab.

The case does not claim exploitation, unauthorized access, persistence, privilege escalation, malware execution, or confirmed Wazuh alerts.

## 2. Environment and Architecture

| Component | Reconstructed value | Role |
|---|---|---|
| Controlled operator | Kali Linux — `192.168.56.106` | Initiates the authorized remote-management session |
| Target endpoint | Windows 11 / `WIN11-LAB` — `192.168.56.105` | Receives the remote session and generates telemetry |
| Test identity | `LAB\soc-test` | Dedicated illustrative lab identity; original account evidence unavailable |
| Remote service | WinRM / PowerShell Remoting | Remote administration and execution channel |
| Wazuh endpoint | Agent `002` | Expected Windows log collector based on the preceding cases |
| SOC platform | Wazuh Manager, Indexer, and Dashboard | Expected ingestion, search, and correlation path |
| Network | Isolated host-only network `192.168.56.0/24` | Authorized laboratory boundary |

![Case 10 reconstructed architecture](../../screenshots/Case%2010%20-%20Remote%20Execution/01-case10-architecture-reconstructed.png)

**What this image proves:** nothing about a historical event. It documents the intended evidence flow and the systems that should be correlated during revalidation.

## 3. Detection Details

| Attribute | Expected or reconstructed value |
|---|---|
| Detection source | Windows Security, PowerShell Operational, WinRM Operational, optional Sysmon, and Wazuh |
| Successful authentication | Security Event ID `4624`; Logon Type `3` represents a network logon |
| Explicit credentials | Security Event ID `4648` may be relevant when explicit credentials are used; presence is implementation-dependent |
| PowerShell module logging | Event ID `4103`, when enabled |
| PowerShell script-block logging | Event ID `4104`, when enabled |
| Process creation | Security Event ID `4688`, when Audit Process Creation is enabled |
| Command-line visibility | Requires the process command-line audit policy; it is not enabled by default |
| WinRM context | `Microsoft-Windows-WinRM/Operational`; exact events depend on configuration and client behavior |
| Wazuh result | Not available; no original Case 10 alert or raw event survived |
| Detection logic | Correlate source IP, target host, user, logon identifier, process ancestry, command content, and event time within a short window |

Microsoft documents Event ID `4624` as a successful logon and Logon Type `3` as a network logon. Event ID `4688` records process creation and can be correlated with a logon identifier. PowerShell module and script-block logging produce Events `4103` and `4104` when the relevant policies are enabled.

## 4. Entities and Key Attributes

| Entity | Value | Investigative relevance |
|---|---|---|
| Source host | Kali Linux | Controlled system used to initiate the illustrated session |
| Source IP | `192.168.56.106` | Origin of the reconstructed remote-management activity |
| Destination host | `WIN11-LAB` | Endpoint whose authentication and execution telemetry must be correlated |
| Destination IP | `192.168.56.105` | Windows endpoint receiving the remote session |
| Destination service | WinRM / WS-Management | Remote execution channel; commonly TCP `5985` for HTTP or `5986` for HTTPS |
| Identity | `LAB\soc-test` | Illustrative authorized test account; not recovered from original evidence |
| Expected process context | `svchost.exe` → `wsmprovhost.exe` → PowerShell execution context | Useful process ancestry for investigating WinRM activity; exact chain varies by implementation |
| Wazuh agent | `002` | Expected endpoint identity based on the preceding repository cases |
| Files and hashes | Not available | No recovered file artifact was used in this reconstruction |
| Session and logon ID | Not available | Required for definitive cross-event correlation during revalidation |

## 5. Reconstructed Activity Flow

The illustrated activity is intentionally harmless: establishing an authorized remote-management session and requesting basic system information such as hostname, time, or service state.

![Case 10 reconstructed remote session](../../screenshots/Case%2010%20-%20Remote%20Execution/02-case10-remote-session-reconstructed.png)

**What this image proves:** it demonstrates the intended operator-to-endpoint narration. It does not prove that the displayed command, date, account, or connection existed in the lost lab.

| Sequence | Activity | Expected telemetry | Validation state |
|---|---|---|---|
| 1 | Source reaches the Windows WinRM service | Network connection and firewall telemetry | Not available |
| 2 | Test identity authenticates | Event `4624`, commonly Logon Type `3`; `4648` may appear depending on credential use | Not available |
| 3 | WinRM creates a remote execution context | WinRM Operational records and `wsmprovhost.exe` process context | Not available |
| 4 | Harmless PowerShell commands run | PowerShell `4103`/`4104` when enabled; process event `4688` when enabled | Not available |
| 5 | Wazuh agent forwards configured channels | Wazuh event documents containing agent, host, user, source, process, and rule fields | Not available |
| 6 | Analyst correlates the activity | Shared time window, identity, source, host, process ancestry, and command context | Reconstructed only |

## 6. Expected Windows Telemetry

![Case 10 reconstructed Windows telemetry](../../screenshots/Case%2010%20-%20Remote%20Execution/03-case10-windows-telemetry-reconstructed.png)

**What this image proves:** it is an educational correlation model. The timestamps, process IDs, account, commands, and event details are fictional examples and must not be cited as captured evidence.

During revalidation, an analyst should confirm:

1. Event `4624` identifies the expected account, target, source network address, authentication package, and Logon Type `3`.
2. The logon ID can be correlated with process and session activity where Windows exposes the same identifier.
3. WinRM Operational events align with the authentication window.
4. PowerShell `4103` or `4104` records the harmless command content when the required logging is enabled.
5. Event `4688` records relevant process creation and parent-process information.
6. Command-line data is present only when the appropriate audit policy is enabled and must be reviewed for exposed secrets before publication.

## 7. Expected Wazuh Correlation

![Case 10 reconstructed Wazuh correlation](../../screenshots/Case%2010%20-%20Remote%20Execution/04-case10-wazuh-correlation-reconstructed.png)

**What this image proves:** it shows the expected analyst workflow and limitations. It is not a Wazuh export and does not claim that a Wazuh rule fired.

The useful Wazuh view should connect:

```text
Source 192.168.56.106
        ↓
Network logon on WIN11-LAB
        ↓
WinRM execution context
        ↓
PowerShell activity
        ↓
Process creation and ancestry
        ↓
Agent 002 ingestion
        ↓
Analyst correlation and verdict
```

A future custom analytic should alert on an unusual or unauthorized WinRM source, privileged account, unexpected target, suspicious PowerShell content, or remote execution followed by persistence or lateral movement. A remote-management event alone is not proof of compromise.

## 8. Analysis and Findings

### Finding 1 — Identity and source context are essential

The same WinRM behavior can represent legitimate administration or attacker lateral movement. The source host, account authorization, target role, time, and change record determine whether the activity is expected.

### Finding 2 — One event is insufficient

Event `4624` can establish network authentication, but it does not prove which command ran. PowerShell logging can show command content, while process auditing can show process ancestry. The strongest conclusion comes from correlating all available sources.

### Finding 3 — Visibility depends on configuration

PowerShell script-block logging, module logging, process creation auditing, command-line capture, WinRM Operational logging, and Wazuh channel collection must be enabled before the activity occurs. Missing configuration creates a detection gap that cannot be repaired after evidence is lost.

### Finding 4 — The reconstructed images are narrative artifacts

The images make the expected workflow understandable to public readers. They are deliberately watermarked and cannot be used as event evidence.

## 9. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Reason for mapping | Evidence status |
|---|---|---|---|---|
| Lateral Movement | Windows Remote Management | [`T1021.006`](https://attack.mitre.org/techniques/T1021/006/) | WinRM allows authenticated interaction and command execution on a remote Windows system | Conceptual mapping; no original Case 10 event evidence |
| Execution | PowerShell | [`T1059.001`](https://attack.mitre.org/techniques/T1059/001/) | PowerShell provides the reconstructed command-execution context | Conceptual mapping; no original Case 10 script-block evidence |

MITRE mappings describe behavior. They do not establish malicious intent or confirm that a compromise occurred.

## 10. Constraints and Limitations

- The original home-lab device, virtual machines, volatile data, and Case 10 telemetry were lost.
- No original Event Viewer export, Wazuh alert document, `alerts.json` record, packet capture, process tree, command history, or screenshot is available.
- The historical Case 10 event time, alert time, ingestion time, session ID, logon ID, PIDs, rule ID, decoder, and exact authentication package are unknown.
- The IP addresses, agent number, and endpoint role are inherited from Cases 7–9 and are used only to keep the portfolio narrative consistent.
- The generated images contain fictional timestamps, PIDs, commands, and UI layouts for explanation.
- A future lab must validate which events appear for the selected client, authentication method, Windows build, audit policy, PowerShell version, and Wazuh configuration.
- This case cannot support claims of compromise, successful detection, rule performance, attribution, or data loss.

## 11. Analyst Verdict

- **Classification:** Inconclusive for event-specific detection; reconstructed authorized lab scenario
- **Authorization:** Authorized by design
- **Scope:** One illustrated source host, one Windows lab endpoint, one test identity, and one expected Wazuh agent
- **Confidence:** Low for historical-event validation; medium for the investigation and telemetry model
- **Root cause:** Original evidence unavailable following loss of the lab device
- **Conclusion:** The reconstructed workflow is consistent with how authorized WinRM and PowerShell Remoting can be investigated, but no historical Case 10 event can be independently verified.

## 12. Response and Recommendations

No containment or eradication action is warranted for the reconstructed, authorized scenario.

Before repeating this case in a replacement lab:

1. Rebuild an isolated host-only network and create clean VM snapshots.
2. Use a dedicated, non-production test identity with minimum required privileges.
3. Restrict WinRM to the lab subnet and selected source host.
4. Enable and verify Security process creation auditing and command-line capture.
5. Enable PowerShell module and script-block logging, with protected logging where appropriate.
6. Enable WinRM Operational logging and confirm Wazuh collects every required channel.
7. Establish a baseline before the remote session.
8. Capture raw events, timestamps with timezone, logon IDs, process IDs, and Wazuh document identifiers.
9. Export evidence before cleanup and preserve a checksum-backed evidence index.
10. Replace these reconstructed images with real, redacted screenshots after revalidation.

## 13. Evidence Index

| Artifact | Type | Evidentiary value |
|---|---|---|
| [01 — Architecture](../../screenshots/Case%2010%20-%20Remote%20Execution/01-case10-architecture-reconstructed.png) | Generated diagram | Explains the intended system and evidence flow; not event evidence |
| [02 — Remote session flow](../../screenshots/Case%2010%20-%20Remote%20Execution/02-case10-remote-session-reconstructed.png) | Generated terminal mockup | Explains the authorized activity narrative; not command evidence |
| [03 — Windows telemetry](../../screenshots/Case%2010%20-%20Remote%20Execution/03-case10-windows-telemetry-reconstructed.png) | Generated Event Viewer mockup | Explains expected correlation fields; not a log export |
| [04 — Wazuh correlation](../../screenshots/Case%2010%20-%20Remote%20Execution/04-case10-wazuh-correlation-reconstructed.png) | Generated SIEM mockup | Explains the expected analyst view; not a Wazuh screenshot |

## 14. References

- [MITRE ATT&CK — Windows Remote Management, T1021.006](https://attack.mitre.org/techniques/T1021/006/)
- [MITRE ATT&CK — PowerShell, T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft — Event 4624: An account was successfully logged on](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)
- [Microsoft — Event 4688: A new process has been created](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)
- [Microsoft — PowerShell logging](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1)
- [Microsoft — Command-line process auditing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)

## Case Closure

**Case 10 — Remote Execution is closed as a reconstructed proof of concept.** The case documents an authorized WinRM and PowerShell Remoting evidence path from `192.168.56.106` to `WIN11-LAB` (`192.168.56.105`), through expected Windows telemetry and Wazuh Agent `002`. Because the original device and telemetry are unavailable, the event-specific verdict remains **inconclusive with low confidence**. The documentation is complete for public disclosure, every visual is marked as reconstructed, and live technical validation remains a future follow-up when the lab is rebuilt.
