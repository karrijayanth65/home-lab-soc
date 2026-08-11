# Windows Scheduled Task Creation and Execution — Event ID 4698

## Case Overview

This investigation demonstrates the detection and investigation of a controlled Windows Scheduled Task creation using Windows Security Event ID 4698 and Wazuh.

A disposable lab task named `SOC-Lab-4698-Test` was created on the Windows 10 laboratory endpoint. The task was configured to execute `notepad.exe` using a one-time trigger.

The investigation validated:

- Windows Event ID 4698 — Scheduled Task Created
- Wazuh ingestion and detection of Event ID 4698
- Wazuh Rule 60228
- MITRE ATT&CK T1053 — Scheduled Task/Job
- Scheduled task configuration and trigger state
- Process creation through Windows Event ID 4688
- Correlation of the scheduled task with `notepad.exe`
- Scheduled task deletion through Windows Event ID 4699
- Endpoint cleanup
- A Wazuh visibility/detection gap for Event ID 4699

---

## Lab Environment

| Component | Value |
|---|---|
| Windows endpoint | Windows-10-Lab |
| Wazuh Agent | `001` |
| Windows IP | `192.168.56.104` |
| Windows Event Channel | Security |
| Wazuh Rule | `60228` |
| MITRE Technique | `T1053` |
| Technique | Scheduled Task/Job |
| Controlled Task | `SOC-Lab-4698-Test` |
| Task Action | `notepad.exe` |

---

# 1. Investigation Objective

The objective was to generate a controlled Scheduled Task creation event and follow the activity through the Windows event logs and Wazuh.

The investigation specifically aimed to determine whether:

1. Windows generated Event ID 4698 when the task was created.
2. Wazuh ingested and detected the event.
3. The Wazuh detection mapped the activity to MITRE ATT&CK.
4. The scheduled task configuration could be validated locally.
5. Execution of the configured action could be correlated with Windows Event ID 4688.
6. Task deletion generated Event ID 4699.
7. Wazuh also provided visibility for the deletion event.

---

# 2. Enable Windows Audit Telemetry

The Windows endpoint was configured to audit the relevant Scheduled Task activity.

The audit configuration was verified before generating the controlled test event.

**Evidence:**

`PS_01_4698_audit_enabled.png`

![Windows Scheduled Task audit configuration](../screenshots/Case%206/PS_01_4698_audit_enabled.png)

---

# 3. Create the Controlled Scheduled Task

A controlled scheduled task was created using Administrator PowerShell.

The task was intentionally named:

```text
SOC-Lab-4698-Test
````

The action was:

```text
notepad.exe
```

A one-time trigger was configured.

The resulting task was initially registered successfully and reported a `Ready` state.

**Evidence:**

`PS_02_4698_task_created.png`

![Scheduled task creation](../screenshots/Case%206/PS_02_4698_task_created.png)

---

# 4. Windows Event ID 4698

Windows generated Security Event ID 4698:

```text
A scheduled task was created.
```

The event contained the controlled task name:

```text
\SOC-Lab-4698-Test
```

The event also exposed the task XML, including the configured action:

```text
<Command>notepad.exe</Command>
```

This confirmed that Windows Security auditing recorded the creation of the controlled scheduled task.

**Evidence:**

`PS_03_4698_task_created_event.png`

![Windows Event ID 4698](../screenshots/Case%206/PS_03_4698_task_created_event.png)

---

# 5. Wazuh Ingestion of Event ID 4698

The Windows Event ID 4698 was successfully ingested by Wazuh.

The Wazuh event showed:

```text
Event ID: 4698
Task Name: \SOC-Lab-4698-Test
Rule ID: 60228
Rule Description: A scheduled task was created
Rule Level: 4
```

This established that the controlled Windows event was visible in the Wazuh platform.

**Evidence:**

`Wazuh_01_4698_ingested.png`

![Wazuh Event ID 4698 ingestion](../screenshots/Case%206/Wazuh_01_4698_ingested.png)

---

# 6. Wazuh Event Details

The Wazuh document details provided the underlying Windows event fields.

Important fields included:

```text
data.win.system.eventID: 4698
data.win.eventdata.taskName: \SOC-Lab-4698-Test
data.win.system.channel: Security
data.win.eventdata.subjectUserName: Windows Lab
```

The task XML was also present in the event data.

The XML confirmed that the controlled task was configured to execute:

```text
notepad.exe
```

**Evidence:**

`Wazuh_02_4698_task_details.png`

![Wazuh Event 4698 task details](../screenshots/Case%206/Wazuh_02_4698_task_details.png)

---

# 7. Wazuh Detection and MITRE ATT&CK Mapping

Wazuh generated Rule `60228` for the event.

Detection details:

| Field       | Value                                        |
| ----------- | -------------------------------------------- |
| Rule ID     | `60228`                                      |
| Rule Level  | `4`                                          |
| Description | A scheduled task was created                 |
| MITRE ID    | `T1053`                                      |
| Technique   | Scheduled Task/Job                           |
| Tactics     | Execution, Persistence, Privilege Escalation |

The Wazuh rule therefore provided an ATT&CK-aligned detection for the controlled Scheduled Task creation.

**Evidence:**

`Wazuh_03_rule_60228_T1053.png`

![Wazuh Rule 60228 MITRE mapping](../screenshots/Case%206/Wazuh_03_rule_60228_T1053.png)

---

# 8. Validate Scheduled Task Configuration

The task was then validated directly on the Windows endpoint.

The endpoint reported:

```text
TaskName : SOC-Lab-4698-Test
TaskPath : \
State    : Running
```

The configured action was:

```text
Execute: notepad.exe
```

The trigger was enabled and contained the expected one-time start boundary.

This confirmed that the task existed in the endpoint configuration and had progressed beyond simple creation.

**Evidence:**

`PS_04_task_validation.png`

![Scheduled task validation](../screenshots/Case%206/PS_04_task_validation.png)

---

# 9. Process Execution Correlation

The scheduled task was configured to execute `notepad.exe`.

Windows Security Event ID 4688 subsequently recorded the process creation.

The process event contained:

```text
New Process Name:
C:\Windows\System32\notepad.exe
```

and:

```text
New Process ID:
0x161c
```

The hexadecimal process ID corresponds to PID `5660`.

The event also identified the creator process:

```text
Creator Process Name:
C:\Windows\System32\svchost.exe
```

This provided process-level telemetry associated with the scheduled task execution.

**Evidence:**

`WZ_03_4688_notepad_process_creation.png`

![Windows Event 4688 process creation](../screenshots/Case%206/WZ_03_4688_notepad_process_creation.png)

---

# 10. PID Correlation

The process creation evidence was correlated using the process identifier.

Windows reported:

```text
New Process ID: 0x161c
```

which corresponds to:

```text
PID 5660
```

The controlled task execution evidence therefore established the relationship between the scheduled task action and the resulting `notepad.exe` process.

**Evidence:**

`WZ_07_Event4688_Notepad_PID161c_Correlation.png`

![PID correlation](../screenshots/Case%206/WZ_07_Event4688_Notepad_PID161c_Correlation.png)

---

# 11. Scheduled Task Cleanup

After the investigation was complete, the controlled scheduled task was removed.

Before deletion, the task was confirmed to exist and was in the `Running` state.

The task was then removed using:

```powershell
Unregister-ScheduledTask -TaskName "SOC-Lab-4698-Test" -Confirm:$false
```

A subsequent lookup returned no task, confirming successful removal.

**Evidence:**

`PS_05_4698_cleanup.png`

![Scheduled task cleanup](../screenshots/Case%206/PS_05_4698_cleanup.png)

---

# 12. Process Cleanup

Because the scheduled task had executed `notepad.exe`, the remaining Notepad processes were checked.

The endpoint showed two `notepad.exe` processes, including PID `5660`.

The Notepad processes were terminated in the disposable laboratory VM.

A subsequent process query returned no `notepad.exe` processes.

**Evidence:**

`PS_06_process_cleanup.png`

![Process cleanup](../screenshots/Case%206/PS_06_process_cleanup.png)

---

# 13. Windows Event ID 4699 — Scheduled Task Deleted

Windows subsequently generated Security Event ID 4699:

```text
A scheduled task was deleted.
```

The event specifically identified:

```text
Task Name:
\SOC-Lab-4698-Test
```

This confirmed that Windows recorded deletion of the controlled scheduled task.

**Evidence:**

`PS_07_4699_task_deleted.png`

![Windows Event ID 4699](../screenshots/Case%206/PS_07_4699_task_deleted.png)

---

# 14. Wazuh Visibility Check for Event ID 4699

A Wazuh query was performed for:

```text
agent.id:001 AND data.win.system.eventID:4699
```

No matching Wazuh alert was returned.

A more specific query for:

```text
agent.id:001 AND data.win.system.eventID:4699 AND data.win.eventdata.taskName:*SOC-Lab-4698-Test*
```

also returned no results.

This initially raised the question of whether the Wazuh agent was still receiving Windows Security telemetry.

---

# 15. Confirm General Security Event Ingestion

A broader Wazuh query for Security-channel events returned more than 1,000 events from the Windows endpoint.

Events were visible around the same period as the task cleanup.

This demonstrated that the Wazuh agent was still actively forwarding Windows Security telemetry.

Therefore, the absence of the 4699 alert could not simply be attributed to a disconnected agent or complete Security-channel ingestion failure.

**Evidence:**

`Wazuh_04_security_events_cleanup_window.png`

![Wazuh Security events around cleanup](../screenshots/Case%206/Wazuh_04_security_events_cleanup_window.png)

---

# 16. Wazuh Ruleset Investigation

The Wazuh manager was then inspected to determine whether an exact rule for Windows Event ID 4699 existed.

The manager was running inside the Docker container:

```text
single-node-wazuh.manager-1
```

A broad search initially returned a misleading match:

```text
rule id="44699"
```

because the string `4699` appeared inside another rule ID.

An exact rule-ID search for:

```text
<rule id="4699"
```

returned no result.

This established that the installed Wazuh ruleset did not contain an exact rule for Windows Event ID 4699.

No Wazuh rule modifications were made during this investigation.

---

# 17. Detection Gap

The investigation therefore identified the following visibility difference:

| Activity                        | Windows |                Wazuh |
| ------------------------------- | ------: | -------------------: |
| Scheduled Task Created — 4698   |       ✅ |         ✅ Rule 60228 |
| Scheduled Task Execution — 4688 |       ✅ |  ✅ Process detection |
| Scheduled Task Deleted — 4699   |       ✅ | ⚠️ No matching alert |

The endpoint generated the 4699 event successfully, while Wazuh continued receiving other Security events but did not surface the 4699 event as an alert.

This represents a **detection/alerting gap for Windows Event ID 4699 in the current Wazuh ruleset**.

---

# 18. Final Endpoint State

The controlled laboratory artifacts were removed.

Final cleanup checks confirmed:

```text
Scheduled Task:
SOC-Lab-4698-Test
```

was no longer present.

The `notepad.exe` processes created during the controlled test were also terminated.

The endpoint was therefore returned to a clean state with respect to the artifacts created during this investigation.

---

# 19. Investigation Timeline

```text
Task creation
     │
     ▼
Windows Event 4698
     │
     ▼
Wazuh Rule 60228
     │
     ▼
MITRE T1053 — Scheduled Task/Job
     │
     ▼
Task configuration validated
     │
     ▼
notepad.exe executed
     │
     ▼
Windows Event 4688
     │
     ▼
PID 5660 / 0x161c correlation
     │
     ▼
Task removed
     │
     ▼
Windows Event 4699
     │
     ▼
No Wazuh 4699 alert
     │
     ▼
Detection gap identified
```

---

# Conclusion

This controlled investigation successfully demonstrated end-to-end telemetry for Windows Scheduled Task creation.

Windows Event ID 4698 was generated when `SOC-Lab-4698-Test` was created and was successfully detected by Wazuh Rule `60228`, which mapped the activity to MITRE ATT&CK `T1053 — Scheduled Task/Job`.

The task configuration was independently validated on the endpoint, and its configured `notepad.exe` action was correlated with Windows Event ID 4688 and process ID `5660` (`0x161c`).

The scheduled task was subsequently removed, producing Windows Event ID 4699. However, no corresponding Wazuh alert was observed. Additional investigation confirmed that the Wazuh agent continued forwarding Windows Security events and that the installed Wazuh ruleset did not contain an exact rule for Event ID 4699.

The final result was therefore both a successful detection exercise and a documented detection gap:

> **Wazuh successfully detected Scheduled Task creation through Event ID 4698, but the current ruleset did not provide equivalent alerting for Scheduled Task deletion through Event ID 4699.**

The controlled task and associated processes were removed from the laboratory endpoint after testing.