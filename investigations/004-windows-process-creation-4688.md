# Investigation 004 — Windows Process Creation Monitoring (Event ID 4688)

## 1. Investigation Overview

This investigation demonstrates how Windows records the creation of a new process and how Wazuh receives and detects that activity.

The test was performed in an isolated Windows 10 SOC lab environment using a controlled and intentionally benign process execution.

The objective was to understand the complete telemetry path:

```text
Controlled Process Execution
        ↓
Windows Security Auditing
        ↓
Security Event ID 4688
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Wazuh Detection Rule
        ↓
SOC Investigation
````

The process used for the test was `notepad.exe`.

The test was intentionally benign and was performed only to generate process-creation telemetry for analysis.

---

## 2. Investigation Objective

The objectives of this investigation were:

* Understand Windows Process Creation auditing.
* Determine the initial Process Creation audit configuration.
* Enable successful Process Creation auditing.
* Generate a controlled process-creation event.
* Identify Windows Security Event ID `4688`.
* Verify that Wazuh receives the event.
* Identify the Wazuh detection rule associated with the event.
* Investigate the new process and its parent process.
* Understand how process-creation telemetry can support SOC investigations.

The investigation focuses on understanding the telemetry and detection process rather than simulating malicious activity.

---

## 3. Lab Environment

The investigation was performed inside an isolated SOC laboratory environment.

The Windows endpoint used for the test was:

```text
Windows-10-Lab
```

The endpoint was connected to the Wazuh manager used by the lab.

The test activity was intentionally generated from PowerShell:

```text
powershell.exe
        ↓
notepad.exe
```

No production systems or production security telemetry were used.

> **Lab Environment Notice:** All hosts, accounts, IP addresses, events, and security telemetry shown in this investigation were generated within an isolated, intentionally configured SOC lab environment.

---

## 4. Understanding Windows Process Creation Auditing

Windows can record process-creation activity through its Security auditing subsystem.

The relevant audit subcategory for this investigation is:

```text
Detailed Tracking
    └── Process Creation
```

When Process Creation auditing is enabled, Windows can generate Security Event ID `4688` when a new process is created.

Event ID `4688` is therefore useful because it can provide information about:

* The newly created process.
* The process that created it.
* The account associated with the activity.
* Process-related identifiers.
* Other contextual information recorded by Windows.

For a SOC analyst, this type of telemetry can help establish how a process started and what its parent process was.

---

## 5. Initial Audit Configuration

Before changing the Windows configuration, the current Process Creation audit state was checked.

The command used was:

```powershell
auditpol /get /subcategory:"Process Creation"
```

The initial configuration showed:

```text
Process Creation    No Auditing
```

This established the baseline before making any configuration change.

### Evidence — Initial Configuration

![Initial Process Creation audit configuration](../screenshots/Case%204/PS_01_process_creation_audit_before.png)

**Evidence file:** `PS_01_process_creation_audit_before.png`

This screenshot demonstrates that Process Creation auditing was initially disabled.

Establishing this baseline is important because it allows the configuration change to be clearly documented rather than assuming that the required auditing was already enabled.

---

## 6. Enabling Process Creation Auditing

Process Creation auditing was then enabled using:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

Windows reported that the command was successfully executed.

The configuration was then verified again using:

```powershell
auditpol /get /subcategory:"Process Creation"
```

The resulting configuration showed:

```text
Process Creation    Success
```

This confirmed that successful process-creation auditing was enabled.

### Evidence — Auditing Enabled

![Process Creation auditing enabled](../screenshots/Case%204/PS_02_process_creation_audit_enabled.png)

**Evidence file:** `PS_02_process_creation_audit_enabled.png`

This screenshot demonstrates the transition from the initial state of `No Auditing` to successful Process Creation auditing.

The verification step is important because issuing a configuration command alone does not prove that the intended configuration is active.

---

## 7. Controlled Process Execution

After Process Creation auditing was enabled, a controlled process was launched:

```powershell
notepad.exe
```

Notepad was used because it is a normal Windows application and provides a safe way to generate process-creation telemetry.

The test relationship was:

```text
Windows PowerShell
        |
        | creates
        v
notepad.exe
```

After the process was created, the Windows Security event log was queried for Event ID `4688`.

The command used was:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id = 4688
} -MaxEvents 5 |
Select-Object TimeCreated, Id, Message |
Format-List
```

---

## 8. Windows Security Event ID 4688

The Windows event query returned:

```text
Event ID: 4688

Message:
A new process has been created.
```

The event also contained process information showing:

```text
New Process Name:
C:\Windows\System32\notepad.exe
```

and:

```text
Creator Process Name:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This is important because Event ID `4688` provides more than simply the fact that a process was created.

It provides a relationship between the newly created process and its creator.

In this test:

```text
powershell.exe
      |
      +----> notepad.exe
```

### Evidence — Windows Event 4688

![Windows Security Event 4688](../screenshots/Case%204/Win_01_event_4688.png)

**Evidence file:** `Win_01_event_4688.png`

This screenshot demonstrates that Windows generated Security Event ID `4688` for the controlled process creation.

It also provides the process and creator-process information used later during the Wazuh investigation.

---

## 9. Verifying Wazuh Ingestion

After confirming that Windows generated Event ID `4688`, the next question was:

> Did Wazuh receive the event?

The Wazuh Threat Hunting interface was queried using:

```text
agent.id:001 AND data.win.system.eventID:4688
```

The search returned multiple process-creation events from the Windows lab endpoint.

The results included Wazuh Rule ID:

```text
67027
```

with the description:

```text
A process was created.
```

and rule level:

```text
3
```

This confirmed that Windows process-creation telemetry was being received and processed by Wazuh.

### Evidence — Wazuh Event Ingestion

![Wazuh Event 4688 ingestion](../screenshots/Case%204/Wazuh_01_event_4688_ingested.png)

**Evidence file:** `Wazuh_01_event_4688_ingested.png`

This screenshot demonstrates that Wazuh received Windows Event ID `4688` from the `Windows-10-Lab` agent.

The initial search returned multiple events because normal system activity can generate many process-creation events.

---

## 10. Examining the Wazuh Event Details

One of the Wazuh events was opened to inspect its detailed fields.

The event showed:

```text
New Process Name:
C:\Windows\System32\notepad.exe
```

and:

```text
Parent Process Name:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This confirmed that the process observed by Wazuh was the same controlled `notepad.exe` process created during the test.

The Wazuh event also identified:

```text
Rule ID: 67027
Rule Description: A process was created.
Rule Level: 3
Event ID: 4688
```

### Evidence — Wazuh Event Details

![Wazuh Event 4688 details](../screenshots/Case%204/Wazuh_02_event_4688_details.png)

**Evidence file:** `Wazuh_02_event_4688_details.png`

This screenshot demonstrates that Wazuh preserved the important process-creation fields from the Windows event.

---

## 11. Filtering the Controlled Test Event

The initial Wazuh query returned multiple Event ID `4688` events.

To isolate the controlled test, the search was narrowed using the `newProcessName` field.

The first attempts used an exact Windows path. Those searches returned no results.

This did not indicate a telemetry failure.

The broader wildcard search was then used:

```text
agent.id:001 AND data.win.system.eventID:4688 AND data.win.eventdata.newProcessName:*notepad*
```

This returned a single matching event.

This troubleshooting process demonstrated an important SOC investigation technique:

```text
Broad Search
    ↓
Identify Relevant Event
    ↓
Narrow the Search
    ↓
Use a Distinctive Field
    ↓
Isolate the Controlled Activity
```

### Evidence — Filtered Notepad Event

![Filtered notepad Event 4688](../screenshots/Case%204/Wazuh_03_filtered_notepad_4688.png)

**Evidence file:** `Wazuh_03_filtered_notepad_4688.png`

This screenshot demonstrates that the controlled `notepad.exe` process could be isolated from the larger collection of process-creation events.

---

## 12. Final Event Analysis

The isolated Wazuh event was opened for detailed analysis.

The final event confirmed the following relationship:

```text
Parent Process:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

        |
        | created
        v

New Process:
C:\Windows\System32\notepad.exe
```

The event also confirmed:

```text
Windows Event ID: 4688
Wazuh Rule ID: 67027
Rule Description: A process was created.
Rule Level: 3
```

The Wazuh event was decoded through:

```text
windows_eventchannel
```

and the event originated from the Windows Security channel.

### Evidence — Final Wazuh Event Details

![Final Wazuh Event 4688 details](../screenshots/Case%204/Wazuh_04_filtered_event_details.png)

**Evidence file:** `Wazuh_04_filtered_event_details.png`

This is the primary evidence showing the relationship between the controlled process, its parent process, Windows Event ID `4688`, and Wazuh Rule `67027`.

---

## 13. Detection Assessment

The Wazuh detection identified the activity with:

```text
Rule ID: 67027
Rule Level: 3
Description: A process was created.
```

The detection successfully identified process-creation activity.

However, an important SOC distinction must be made:

> A detection alert does not automatically mean that malicious activity occurred.

In this investigation, the process creation was intentionally generated by the analyst.

Therefore:

```text
Detection:
    True Positive

Security Classification:
    Benign / Expected Lab Activity
```

The detection was correct because a process was genuinely created.

It was not malicious because the process execution was intentionally performed as part of the controlled laboratory test.

---

## 14. Why Process Creation Telemetry Matters

Process Creation telemetry is valuable to a SOC analyst because it can provide context around executable activity.

An analyst can investigate questions such as:

* What process was created?
* Which process created it?
* Which account was associated with the activity?
* When did the process start?
* Is the executable expected?
* Is the parent-child relationship normal?
* Does the process path look suspicious?
* Does the activity correlate with other security events?

For example, the following relationship may deserve investigation in a real environment:

```text
Office Application
        |
        +----> PowerShell
                  |
                  +----> Suspicious Executable
```

By contrast, the relationship observed in this lab was intentionally created:

```text
PowerShell
    |
    +----> notepad.exe
```

The context determines whether the alert requires escalation.

---

## 15. Relationship to the Previous PowerShell Investigation

This investigation also demonstrates how different Windows telemetry sources provide different information.

The previous PowerShell investigation focused on:

```text
PowerShell Script Block Logging
        ↓
Event ID 4104
        ↓
PowerShell command/script content
```

This investigation focuses on:

```text
Process Creation Auditing
        ↓
Event ID 4688
        ↓
New process + creator process
```

These telemetry sources can complement each other during an investigation.

For example:

```text
PowerShell command activity
        +
Process creation activity
        ↓
Better understanding of execution behavior
```

This is one of the important concepts in SOC analysis:

> Individual events provide pieces of evidence. Correlating related telemetry provides better investigative context.

---

## 16. Investigation Findings

The investigation established the following:

1. Process Creation auditing was initially disabled.
2. Successful Process Creation auditing was enabled.
3. A controlled `notepad.exe` process was launched.
4. Windows generated Security Event ID `4688`.
5. The event identified `notepad.exe` as the new process.
6. The event identified PowerShell as the creator process.
7. Wazuh successfully received the Windows event.
8. Wazuh generated Rule ID `67027`.
9. The controlled event was successfully isolated using a field-based wildcard search.
10. The activity was confirmed as benign because it was intentionally generated as part of the lab.

---

## 17. Evidence Index

The following screenshots support this investigation:

| Evidence                                   | Description                                                                   |
| ------------------------------------------ | ----------------------------------------------------------------------------- |
| `PS_01_process_creation_audit_before.png`  | Initial Process Creation audit state                                          |
| `PS_02_process_creation_audit_enabled.png` | Process Creation auditing successfully enabled                                |
| `Win_01_event_4688.png`                    | Windows Security Event ID 4688                                                |
| `Wazuh_01_event_4688_ingested.png`         | Wazuh ingestion of Event ID 4688                                              |
| `Wazuh_02_event_4688_details.png`          | Detailed Wazuh process-creation event                                         |
| `Wazuh_03_filtered_notepad_4688.png`       | Filtered Wazuh result for the controlled notepad test                         |
| `Wazuh_04_filtered_event_details.png`      | Final event details showing process, parent process, Event ID, and Wazuh rule |

All screenshots are stored under:

```text
screenshots/Case 4/
```

Raw event files were not included in the public investigation repository.

---

## 18. Lessons Learned

This investigation demonstrated several important SOC concepts.

### 18.1 Establish a baseline

Before changing a security configuration, record the initial state.

In this case:

```text
Process Creation = No Auditing
```

was documented before enabling the audit.

### 18.2 Verify configuration changes

After enabling auditing, the configuration was queried again to confirm:

```text
Process Creation = Success
```

### 18.3 Verify telemetry at multiple layers

The investigation did not stop after Windows generated the event.

The telemetry was verified through:

```text
Windows
   ↓
Security Event 4688
   ↓
Wazuh
   ↓
Rule 67027
```

### 18.4 Learn to distinguish detection from maliciousness

Wazuh correctly detected the process creation.

The event was nevertheless benign because the analyst intentionally created it.

### 18.5 Use filtering to reduce noise

The initial search returned many process-creation events.

The investigation progressively narrowed the search until the controlled `notepad.exe` event was isolated.

This is representative of normal SOC investigation methodology.

---

## 19. Conclusion

This investigation successfully demonstrated Windows Process Creation monitoring using Security Event ID `4688` and Wazuh.

A controlled `notepad.exe` process was launched from PowerShell.

Windows recorded the activity as Event ID `4688`, including the new process and its creator process.

Wazuh successfully ingested the event and generated Rule ID `67027`, identifying the activity as a process creation event.

The final analysis confirmed:

```text
PowerShell
    |
    +----> notepad.exe
```

The activity was classified as benign because it was intentionally generated inside the SOC laboratory.

The investigation demonstrates the importance of understanding both the underlying Windows telemetry and the SIEM detection layer when performing endpoint investigations.

---

## 20. Investigation Status

**Status:** Completed

**Primary Windows Event:** `4688`

**Primary Wazuh Rule:** `67027`

**Test Process:** `notepad.exe`

**Parent Process:** `powershell.exe`

**Classification:** Benign controlled laboratory activity

**Evidence:** Captured and documented

**Raw Logs:** Not included in the public repository
