# Case 15 — Full SOC Incident Response Capstone

> **Case type:** End-to-end incident response exercise<br>
> **Severity / priority:** High / P2 in this exercise; escalate on active spread or critical assets<br>
> **Status:** Closed — offline capstone package and assurance tests complete<br>
> **Environment:** Authorized SOC portfolio simulation; Windows endpoint scenario<br>
> **Scenario time:** 12 October 2026, 10:00–12:00 UTC (15:30–17:30 IST)<br>
> **Case owner:** Jayanth Karri<br>
> **Evidence mode:** Controlled fixtures, actual file-integrity checks and executed offline tests<br>
> **Confidence:** High for tested software checks; real endpoint compromise not established

## Executive Summary

A five-stage sequence on `WIN11-LAB` connects network authentication by `lab-admin` to WinRM execution, PowerShell, file decoding and scheduled-task creation. This capstone applies the Case 14 correlation to a controlled dataset and extends it through evidence preservation, scoping, containment decisions, eradication, recovery and residual hunting. The fixture suite identifies one complete host/account chain and retains incomplete activity on a second endpoint for further review. Twelve executed assurance tests pass, including controls that reject altered or missing evidence and unsafe closure states. The verdict is a successful authorized response simulation; endpoint isolation, account changes and cleanup are modeled decisions rather than performed actions.

## 1. Mission and Closure Criteria

Demonstrate the reasoning a SOC analyst needs to move from an alert to defensible closure. The deliverable must contain an evidence manifest, timeline, scope assessment, competing hypotheses, response decisions, recovery acceptance criteria, residual hunt, lessons learned and reproducible tests.

Closure requires all six preserved fixture files to match their SHA-256 values; the expected host/account chain to correlate; eight response stages to occur in order; ownership and supporting artifacts for each stage; and all recovery gates to pass. A negative test must prove that recurrence, absent approval, unhealthy telemetry, remaining persistence or inadequate observation prevents closure.

## 2. Environment and Business Context

| Entity | Scenario value | Investigative significance |
|---|---|---|
| Target | `WIN11-LAB` | Windows test endpoint; no production role assigned |
| Secondary endpoint | `WIN11-LAB-02` | Incomplete decode activity warrants review, not automatic compromise attribution |
| Account | `lab-admin` | Same identity used by the complete fixture chain |
| Remote source | `192.168.56.20` | Private lab address from Case 14 fixtures |
| Collection | Windows Security and Sysmon | Intended sources represented by normalized fixture fields |
| SIEM | Wazuh project design | Live agent, index, decoder and alert identifiers: Not available |
| Sensitive data | None assigned to the exercise | Production confidentiality impact cannot be inferred |
| Protocol / destination port | WinRM; endpoint port Not available | Protocol inference requires corroboration; no packet capture supplied |
| Task | `SOC-Lab-HealthCheck` | Fixture command attempts task creation with a benign health-check action |
| File | `C:\Lab\decoded.txt` | Local counterpart is an inert text artifact; no executable payload |

```text
Remote lab source → Windows endpoint
                     ├─ Security: authentication
                     ├─ Sysmon: process ancestry and commands
                     └─ Task definition and file artifacts
                                ↓
                    Preserve → Correlate → Scope
                                ↓
                    Response decisions → Recovery gates
```

## 3. Detection and Triage

The capstone reuses the [Case 14 specification](../../detections/correlation/case14_multi_stage_attack_chain.yml) and executable correlation logic. Host and user are grouped before evaluation. The required ordered chain is Security `4624` with Logon Type `3`, `wsmprovhost.exe`, PowerShell beneath that parent, `certutil.exe -decode` or `-decodehex`, and `schtasks.exe /Create`, all within 30 minutes. The positive chain spans 420 seconds.

Security `4624` establishes a successful logon; Type `3` indicates a network logon and does not by itself identify WinRM. Sysmon Event `1` supplies process context. Task-creation command execution proves an attempt in the fixture model; deployed validation needs Security `4698`, task XML or task inventory to confirm successful creation. Collection depends on audit policy and Sysmon configuration.

**Triage decision:** Open a high-priority investigation for the complete chain. Do not equate tool usage with malware. Check the administrative source, account owner, maintenance authorization, file provenance and task action before classifying activity.

![Simulated investigation view](../../screenshots/Case%2015%20-%20SOC%20Incident%20Response%20Capstone/01-investigation.png)

*Generated training interface: explains the fixture timeline and triage decision; the machine-readable artifacts below are the validation evidence.*

## 4. Evidence Preservation and Integrity

The [manifest](evidence/manifest.json) records relative paths, byte counts and SHA-256 values computed from the actual repository files. The validator rechecks these bytes before accepting the baseline exercise. The manifest is a reproducibility inventory, not an independently signed chain-of-custody record; a party able to rewrite both content and manifest could defeat this check.

| Artifact | Purpose | What it proves |
|---|---|---|
| [Normalized events](evidence/events.json) | Complete chain and incomplete counterexample | Inputs supplied to offline correlation |
| [Task definition](evidence/task.xml) | Least-privilege logon task with health-check action | Task content considered during analysis; not an exported live task |
| [Inert decoded file](evidence/decoded.txt) | Safe substitute for decoded content | Actual artifact bytes and computed hash, not malware behavior |
| [Scope matrix](evidence/scope.csv) | Distinguish complete and incomplete host activity | Analyst scope assessment of supplied fixtures |
| [Recovery state](evidence/recovery.json) | Model response acceptance conditions | Expected state needed for closure, not endpoint measurement |
| [Exercise record](evidence/exercise.json) | Ordered response actions, roles and evidence references | Full test input for closure assurance |

For a real response, export original EVTX and SIEM records, task XML, relevant files and volatile process/network state. Record collector, acquisition time, source, original location and transfer history; hash originals and analyze copies. Prioritize isolation first if active harm makes preservation delay unacceptable, and record that decision. This exercise makes no such emergency exception.

## 5. Investigation Timeline

All times below are scenario UTC times, not timestamps of real response execution. Ingestion time and live alert time are Not available.

| Time | Activity / decision | Supporting artifact |
|---|---|---|
| 10:00 | Network logon by `lab-admin` from `192.168.56.20` | events.json |
| 10:01 | WinRM provider process | events.json |
| 10:02 | PowerShell under WinRM provider | events.json |
| 10:04 | File decoding with certutil | events.json |
| 10:07 | Scheduled-task creation command | events.json |
| 10:08 | Preserve fixture evidence before response | manifest.json |
| 10:10 | Accept high-priority triage | exercise.json |
| 10:15 | Scope one complete host/account chain; retain second host uncertainty | scope.csv |
| 10:20 | Model host isolation and account restriction | recovery.json |
| 10:35 | Model task removal and artifact quarantine | task.xml / recovery.json |
| 10:50 | Begin modeled recovery observation after logging/service checks | recovery.json |
| 11:50 | Complete modeled 60-minute residual-hunt window | recovery.json |
| 12:00 | Review modeled approval and closure gates | exercise.json |

The secondary events are Case 14's cross-host negative sequence, represented at 12:00–12:07 UTC in the input dataset. They serve as a separate scoping counterexample, not part of the initial response chronology or post-cleanup telemetry.

## 6. Hypotheses, Findings and Impact

| Hypothesis | Supporting facts | Missing discriminator | Decision |
|---|---|---|---|
| Approved remote maintenance | Administrative tools, inert file, benign task action | Actual change authorization and identity-owner confirmation | Plausible; verify before punitive action |
| Unauthorized persistence after remote access | Five ordered behaviors under one account/host | Original endpoint events, task success and authorization | Escalation-worthy pattern, not established compromise |
| Unrelated activity stitched together | Individual tools commonly used legitimately | Process GUID / logon-session linkage | Grouping/order controls reduce risk but cannot eliminate it |

**Observed in the offline run:** one complete `WIN11-LAB` / `lab-admin` chain. The secondary timeline has no complete chain. Its isolated `WIN11-LAB-02` decode event must not be silently discarded; follow-up would examine its parent, user and file context.

**Impact assessment:** remote execution and persistence are represented in the scenario. Credential theft, privilege escalation, exfiltration, malware execution, encryption and business interruption are not demonstrated. Root cause of a real compromise is Not available. The exercise hypothesis is overly broad remote administration access; validate source restrictions and account privilege before treating it as an established cause.

## 7. Response Decision Log

| Stage / owner role | Decision | Tradeoff and acceptance evidence |
|---|---|---|
| Preserve / SOC analyst | Capture raw records and artifacts before cleanup | Avoid deleting decisive task/file evidence; verify hashes |
| Triage / SOC analyst | Escalate complete chain with authorization unknown | Protect against premature malware attribution |
| Scope / incident lead | Review source, target, identity and secondary endpoint | Do not claim enterprise-wide containment from one host |
| Contain / endpoint and identity owners | Isolate target while retaining management telemetry; restrict account if unauthorized | Remote management disruption requires approval; emergency isolation depends on harm |
| Eradicate / endpoint owner | Remove confirmed unauthorized task, quarantine file, investigate source and other persistence | Record exact artifacts; do not wipe all scheduled tasks |
| Recover / system owner | Restore approved configuration and test logging/service behavior before reconnecting | Rebuild from trusted image if integrity cannot be established |
| Hunt / SOC analyst | Search all accessible hosts for account, source, task, paths and repeated chains | Document unavailable hosts and retention gaps |
| Review / incident lead | Require owner acceptance and close only within documented scope | Recurrence or missing evidence reopens investigation |

These actions are modeled in [exercise.json](evidence/exercise.json). No endpoint isolation, account restriction, task deletion or stakeholder message was executed by this workflow.

![Response decision simulation](../../screenshots/Case%2015%20-%20SOC%20Incident%20Response%20Capstone/02-response.png)

*Generated response storyboard: shows the decision sequence and role ownership, not a record of actions performed on a device.*

## 8. Recovery and Residual-Hunt Runbook

Require an independently collected result for each production acceptance criterion:

| Check | Evidence to collect in a rebuilt lab | Failure response |
|---|---|---|
| Task absent | Targeted task inventory plus deletion record where auditing is enabled | Return to eradication |
| Artifact quarantined | Exact path status and quarantine metadata | Re-isolate and assess file use |
| Account restricted | Identity change record and fresh-session verification | Complete identity containment |
| Logging healthy | Harmless fresh process/logon event arriving at SIEM | Repair visibility before acceptance |
| Service healthy | Owner-approved functional check | Restore known-good configuration |
| No residual recurrence | Host/account/source/task/path searches over defined time and coverage | Reopen triage and expand scope |
| Owner approval | Named acceptance and exception record | Retain investigating state |

The modeled window is 60 minutes; this is an exercise threshold, not a universal assurance of eradication. A real window depends on task triggers, host availability, retention, ingestion delay and risk. A task that executes at the next logon cannot be cleared by a quiet hour alone: review its definition and test the relevant trigger safely.

Suggested hunt fields: host, normalized domain/account, source IP, event time, image, parent image, command line, task name/action, file path and hash. Use Process GUID and Logon ID when available. Zero hits with missing telemetry is **inconclusive**, which is why logging health and hunt completion are separate closure gates.

## 9. Executed Assurance and Negative Tests

From repository root:

```powershell
python tests/case15/test_capstone.py
```

The [validator](../../tests/case15/test_capstone.py) loads preserved fixture bytes, verifies their manifest, groups host/account events, invokes the Case 14 correlation and checks response/recovery gates. The [results](../../tests/case15/results.json) record **12/12 passed**: one accepted baseline and eleven rejected unsafe variants.

| Test | Expected decision |
|---|---|
| Complete exercise | Accept |
| Altered evidence | Reject |
| Missing evidence | Reject |
| Task still present | Reject |
| Telemetry unhealthy | Reject |
| Owner approval absent | Reject |
| Residual hunt incomplete | Reject |
| Recurring activity | Reject |
| Observation too short | Reject |
| Preservation after containment | Reject |
| Incorrect expected scope | Reject |
| Decode stage removed | Reject |

The test mutates in-memory copies; it does not corrupt the saved artifacts. The response state is a fixture. Passing these tests demonstrates the implemented gate logic and cannot prove successful recovery of a live host.

![Recovery acceptance simulation](../../screenshots/Case%2015%20-%20SOC%20Incident%20Response%20Capstone/03-recovery.png)

*Generated closure illustration: summarizes acceptance gates; the recorded test results are the source of the 12/12 count.*

## 10. ATT&CK and Framework Context

| Behavior | ATT&CK mapping | Boundary |
|---|---|---|
| WinRM remote execution context | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Network logon alone is insufficient |
| PowerShell execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Interpreter use can be legitimate |
| File decoding | [T1140](https://attack.mitre.org/techniques/T1140/) | Decode does not imply malicious content |
| Task creation | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Confirm successful creation and task purpose |

The response decisions align with detection, response and recovery concepts in [NIST SP 800-61 Revision 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final). This portfolio exercise is not a certification or a compliance assessment.

## 11. Lessons and Improvement Backlog

| Finding | Improvement / owner role | Acceptance test |
|---|---|---|
| Task command is an attempt, not proof of creation | Collect Security 4698 and task XML / endpoint owner | Confirm event, task definition and actual inventory agree |
| Same host/user can include unrelated sessions | Add Logon ID and Process GUID links / detection engineer | Reject a same-user concurrent-session counterexample |
| Missing telemetry can produce false reassurance | Monitor collection health / SIEM owner | Drop a collector and ensure closure is blocked |
| Account aliases can break grouping | Normalize domain, SID and hostname / detection engineer | Test equivalent identities and similarly named unrelated accounts |
| Time-window tuning is environment-dependent | Measure delay and trigger behavior / SOC analyst | Exercise late events, replay and logon-trigger recurrence |
| Local manifest is mutable | Store immutable original exports and transfer log / evidence custodian | Independently verify signed or protected preservation record |

## 12. Limitations and Verdict

No original EVTX, live Wazuh alert, agent identifier, Process GUID, account SID, packet capture or system isolation receipt is available. The task and recovery state are purpose-built fixtures. Generated images are simulation illustrations and contain no independent evidence. Production containment, eradication, recovery and data-loss conclusions remain unverified.

- **Classification:** Successful authorized offline incident-response simulation.
- **Detection:** One complete host/account chain; incomplete secondary activity retained for follow-up.
- **Confidence:** High for byte-integrity and tested closure logic; live operational outcome undetermined.
- **Closure reason:** Defined capstone package delivered and all twelve assurance cases passed.
- **Next step:** Rebuild the isolated lab and replace modeled states with acquired evidence, then replay Cases 10–15 end to end.

## 13. Evidence Index and References

The preservation inventory is [manifest.json](evidence/manifest.json); the complete decision record is [exercise.json](evidence/exercise.json). Supporting files are linked in Section 4. Reproduction code and recorded outcomes are in [tests/case15](../../tests/case15). Visual prompt themes and provenance are in [the visual production record](visual-prompts.md). The [rebuilt-lab replay guide](lab-replay.md) supplies preparation steps, read-only Windows investigation examples and the acceptance criteria for replacing fixture evidence with captured records.

- [Microsoft: Event 4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)
- [Microsoft: Sysmon process creation](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Microsoft: Event 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698)
- [NIST: Incident response recommendations, SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

## Case Closure

**Case 15 is closed for its defined offline capstone scope.** It documents the remote-access-to-persistence chain on `WIN11-LAB`, preserves six hashed fixture artifacts, records response ownership and acceptance criteria, and passes twelve assurance scenarios. All fifteen planned portfolio cases now have documented deliverables; their distinct evidence modes remain visible in the project index. Live validation and the improvement backlog remain the next development milestone.
