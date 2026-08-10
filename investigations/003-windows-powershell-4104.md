# Investigation 003 — Windows PowerShell Script Block Logging and Wazuh Detection

## 1. Case Overview

This investigation demonstrates how PowerShell activity performed on a Windows endpoint can be logged by Windows, collected by the Wazuh agent, detected by Wazuh, and investigated from the Wazuh Threat Hunting interface.

The purpose of this investigation was to understand and verify the complete detection path rather than simply execute a PowerShell command.

The investigation followed this sequence:

```text
PowerShell Activity
        ↓
PowerShell Script Block Logging
        ↓
Windows Event ID 4104
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Wazuh Detection Rule 91843
        ↓
Wazuh Alert
        ↓
Endpoint Verification
````

The activity was intentionally generated inside the SOC laboratory environment.

The registry modification used in this case was created specifically for testing and should not be considered malicious activity by itself.

---

## 2. Investigation Objectives

The objectives of this case were to:

1. Verify that PowerShell Script Block Logging was working.
2. Generate a controlled PowerShell activity on the Windows endpoint.
3. Confirm that Windows created Event ID 4104.
4. Confirm that the 4104 event contained the PowerShell ScriptBlock.
5. Confirm that the Wazuh agent collected the event.
6. Confirm that Wazuh detected the activity.
7. Identify the Wazuh rule responsible for the detection.
8. Examine the complete Wazuh alert.
9. Verify the registry modification directly on the endpoint.
10. Preserve the investigation evidence for future review.

---

## 3. Lab Environment

The investigation was performed using the Windows endpoint and Wazuh infrastructure in the SOC laboratory.

### Windows Endpoint

```text
Hostname: DESKTOP-9IT05P4
Wazuh Agent Name: Windows-10-Lab
Wazuh Agent ID: 001
Windows Endpoint IP: 192.168.56.104
```

### Wazuh Manager

```text
Wazuh Manager IP: 192.168.56.103
```

The Windows endpoint was connected to the Wazuh manager through the Wazuh agent.

---

## 4. Understanding the Detection Goal

Before performing the final test, it is important to understand what we were trying to prove.

A SOC analyst does not only want to know that PowerShell is running.

The analyst wants to know what PowerShell actually executed.

For this reason, Windows PowerShell Script Block Logging was used.

The important Windows event for this investigation was:

```text
Event ID: 4104
Channel: Microsoft-Windows-PowerShell/Operational
```

Event ID 4104 can contain the PowerShell ScriptBlock that was executed.

This makes the event useful for security monitoring because the analyst can inspect the actual PowerShell activity instead of only seeing that `powershell.exe` started.

---

# 5. Initial Wazuh Agent Validation

Before generating the detection event, the Wazuh agent service was checked on the Windows endpoint.

The following command was used:

```powershell
Get-Service WazuhSvc
```

The service was confirmed to be running:

```text
Status   Name       DisplayName
Running  WazuhSvc  Wazuh
```

The Wazuh agent log was also checked.

The log showed that the agent was analyzing the following Windows event channels:

```text
Security
System
Microsoft-Windows-PowerShell/Operational
```

The log also showed that the agent successfully connected to the Wazuh manager.

This established that the Wazuh agent was operational before the detection test.

---

# 6. PowerShell Script Block Logging

PowerShell Script Block Logging was then investigated.

The relevant Windows event log is:

```text
Microsoft-Windows-PowerShell/Operational
```

The investigation confirmed that Windows was generating Event ID 4104 events.

Earlier testing also demonstrated that normal PowerShell commands could produce 4104 events.

However, simply generating a 4104 event was not enough to prove that the Wazuh detection rule was working.

This distinction became important during troubleshooting.

A working Windows log source does not automatically mean that every Wazuh detection rule will trigger.

Therefore, a controlled PowerShell command was selected that would match an existing Wazuh detection rule.

---

# 7. Controlled Registry Test

A controlled registry location was created for the laboratory test:

```text
HKLM:\Software\SOC-Lab
```

The following command was used:

```powershell
New-Item -Path "HKLM:\Software\SOC-Lab" -Force
```

A specific registry value was then created:

```powershell
New-ItemProperty `
    -Path "HKLM:\Software\SOC-Lab" `
    -Name "WazuhPowerShellTest" `
    -Value "SOC-LAB-4104-RULE-TEST" `
    -PropertyType String `
    -Force
```

The value used for the test was:

```text
SOC-LAB-4104-RULE-TEST
```

Using a unique value made it easier to locate the activity later in Windows event logs and Wazuh.

---

# 8. Evidence — PowerShell Registry Test

<img width="699" height="464" alt="PS_01_registry_test_command" src="https://github.com/user-attachments/assets/d56c2071-f765-4a69-95e7-6cd19b4b885a" />


```text
HKLM:\Software\SOC-Lab
```

and:

```text
WazuhPowerShellTest : SOC-LAB-4104-RULE-TEST
```

### What this screenshot proves

This screenshot proves that the controlled PowerShell registry modification was successfully executed on the Windows endpoint.

The test created a known artifact that could be followed through the rest of the detection pipeline.

---

# 9. Windows Event ID 4104 Verification

After executing the registry modification, Windows Event ID 4104 was searched.

The event log queried was:

```text
Microsoft-Windows-PowerShell/Operational
```

The investigation searched for Event ID:

```text
4104
```

The event contained the PowerShell ScriptBlock associated with the registry modification.

The important ScriptBlock content was:

```powershell
New-ItemProperty `
    -Path "HKLM:\Software\SOC-Lab" `
    -Name "WazuhPowerShellTest" `
    -Value "SOC-LAB-4104-RULE-TEST" `
    -PropertyType String `
    -Force
```

This confirmed that Windows captured the actual PowerShell command.

---

# 10. Evidence — Windows Event ID 4104

<img width="603" height="419" alt="PS_02_event_4104" src="https://github.com/user-attachments/assets/815e0b9a-e311-4495-99a3-a81ddf99d5ae" />

### What this screenshot proves

The screenshot demonstrates that:

```text
Event ID = 4104
```

was generated by:

```text
Microsoft-Windows-PowerShell/Operational
```

and that the event contained the PowerShell ScriptBlock.

The ScriptBlock included the test registry path and the unique test value.

This is the first major point in the investigation where the activity became visible as Windows security telemetry.

---

# 11. Wazuh Collection and Detection

After confirming that Windows generated Event ID 4104, the event was investigated in the Wazuh Threat Hunting interface.

The Wazuh query used was:

```text
agent.id:001 AND data.win.system.eventID:4104
```

The Wazuh interface returned an event associated with the Windows endpoint.

The event was detected by Wazuh rule:

```text
Rule ID: 91843
```

The rule description was:

```text
Powershell executed "New-ItemProperty -Path". Possible addition of new item to registry
```

The rule level was:

```text
3
```

This confirmed that the activity was not only logged by Windows but was also successfully detected by Wazuh.

---

# 12. Evidence — Wazuh Rule 91843

<img width="1294" height="460" alt="Wazuh_03_rule_91843" src="https://github.com/user-attachments/assets/062d9ca0-6772-48a5-b933-a1e482112c81" />

### What this screenshot proves

The screenshot demonstrates that Wazuh successfully processed the Windows event and generated a detection.

The important values are:

```text
Rule ID: 91843
Rule Level: 3
```

Description:

```text
Powershell executed "New-ItemProperty -Path".
Possible addition of new item to registry
```

This proves that the detection pipeline reached the Wazuh rule stage.

---

# 13. Full Wazuh Alert Analysis

The complete Wazuh alert was then examined.

The alert contained information from the original Windows event, including:

```text
Agent:
Windows-10-Lab

Agent ID:
001

Windows Event ID:
4104

Channel:
Microsoft-Windows-PowerShell/Operational
```

The alert also contained the PowerShell ScriptBlock.

The ScriptBlock included:

```text
New-ItemProperty
```

with the registry path:

```text
HKLM:\Software\SOC-Lab
```

and the test property:

```text
WazuhPowerShellTest
```

with the value:

```text
SOC-LAB-4104-RULE-TEST
```

The Wazuh alert also identified:

```text
Rule ID: 91843
Rule Level: 3
```

---

# 14. JSON Evidence

The complete Wazuh alert JSON should be preserved as a separate text file.

Recommended filename:

```text
Wazuh_04_alert_91843.json
```

Place it here:

```text
screenshots/Case 3/Wazuh_04_alert_91843.json
```

The JSON file contains the complete alert payload captured from Wazuh.

This is preferable to copying only selected fields into the Markdown document because the original alert structure can be reviewed later.

---

# 15. How the JSON Evidence Relates to This Investigation

The JSON evidence provides the structured version of the Wazuh alert.

The Markdown investigation explains what happened.

The screenshot shows what the analyst saw in the Wazuh interface.

The JSON preserves the actual alert fields.

Therefore:

```text
Markdown
    ↓
Explains the investigation

Screenshot
    ↓
Provides visual evidence

JSON
    ↓
Provides structured alert evidence
```

This gives the case stronger evidence than using screenshots alone.

---

# 16. Evidence — Full Wazuh Alert

<img width="555" height="319" alt="Wazuh_04_alert_details" src="https://github.com/user-attachments/assets/41014d32-537e-4d32-b27a-24065f5a6e24" />

### Raw JSON Evidence

The complete Wazuh alert is preserved separately:

```markdown
[View the complete Wazuh Rule 91843 JSON alert](../screenshots/Case%203/Wazuh_04_alert_91843.json)
```

This link allows a reviewer to open the complete JSON evidence directly from the investigation.

---

# 17. Important Fields in the Wazuh JSON

The alert contained the following important information.

### Endpoint

```text
Agent Name:
Windows-10-Lab
```

```text
Agent ID:
001
```

### Windows Event

```text
Event ID:
4104
```

```text
Channel:
Microsoft-Windows-PowerShell/Operational
```

### Detection

```text
Rule ID:
91843
```

```text
Rule Level:
3
```

### PowerShell Activity

The ScriptBlock contained:

```text
New-ItemProperty
```

and:

```text
HKLM:\Software\SOC-Lab
```

and:

```text
WazuhPowerShellTest
```

and:

```text
SOC-LAB-4104-RULE-TEST
```

These fields connect the Windows event to the Wazuh detection.

---

# 18. MITRE ATT&CK Information

The Wazuh alert mapped the activity to:

```text
T1059.001 — PowerShell
T1112     — Modify Registry
```

### T1059.001 — PowerShell

The activity involved execution of PowerShell.

### T1112 — Modify Registry

The PowerShell command modified the Windows Registry.

In this laboratory case, the registry modification was intentionally created as a test.

Therefore, the alert should not be interpreted as proof of malicious activity.

The purpose of the detection is to demonstrate that this type of activity can be identified and investigated.

---

# 19. Final Endpoint Verification

After confirming the Wazuh detection, the registry was checked directly on the Windows endpoint.

The following command was used:

```powershell
Get-ItemProperty -Path "HKLM:\Software\SOC-Lab"
```

The output showed:

```text
WazuhPowerShellTest : SOC-LAB-4104-RULE-TEST
```

This confirmed that the test artifact existed on the endpoint.

This is useful because it independently verifies that the intended registry modification actually occurred.

---

# 20. Evidence — Registry Verification

```text
WazuhPowerShellTest : SOC-LAB-4104-RULE-TEST
```

### What this screenshot proves

This confirms that the test registry value existed on the Windows endpoint after the detection was generated.

This provides endpoint-side verification of the controlled activity.

---

# 21. Complete Detection Flow

The complete investigation can now be represented as:

```text
Controlled PowerShell command
             ↓
Registry modification created
             ↓
PowerShell ScriptBlock Logging
             ↓
Windows Event ID 4104
             ↓
Wazuh Agent collected the event
             ↓
Wazuh processed the event
             ↓
Rule 91843 matched the activity
             ↓
Wazuh alert generated
             ↓
Full alert JSON preserved
             ↓
Registry artifact verified
```

This demonstrates a complete endpoint-to-Wazuh detection workflow.

---

# 22. Troubleshooting and What Was Learned

During the investigation, there were several points where the expected Wazuh result was not immediately visible.

The important lesson was to troubleshoot the detection pipeline one layer at a time.

The following questions were used to isolate the problem:

### Question 1 — Is the Wazuh agent running?

The answer was yes.

```text
WazuhSvc
Status: Running
```

### Question 2 — Is the agent connected to the Wazuh manager?

The Wazuh agent log showed:

```text
Connected to the server ([192.168.56.103]:1514/tcp)
```

and later:

```text
Agent is now online.
```

### Question 3 — Is PowerShell Operational logging being monitored?

The Wazuh agent log showed:

```text
Analyzing event log:
'Microsoft-Windows-PowerShell/Operational'
```

### Question 4 — Is Windows actually generating Event ID 4104?

Yes.

The Windows PowerShell Operational log contained Event ID 4104.

### Question 5 — Does the event contain the expected PowerShell activity?

Yes.

The ScriptBlock contained:

```text
New-ItemProperty
```

and the controlled test value.

### Question 6 — Does Wazuh detect the activity?

Yes.

Wazuh generated Rule:

```text
91843
```

This step-by-step approach was important because it prevented configuration changes from being made blindly.

---

# 23. Why the Earlier Test Was Not Considered the Final Detection Test

An earlier test used a simple PowerShell command such as:

```powershell
Write-Output "SOC-LAB-4104-WAZUH-FINAL-TEST"
```

This was useful for verifying PowerShell Script Block Logging.

However, that test was not sufficient to prove that the specific Wazuh registry-related detection rule would trigger.

The final test used:

```powershell
New-ItemProperty
```

because this activity matched Wazuh Rule 91843.

This demonstrated an important SOC concept:

```text
Log generation
        ≠
Detection generation
```

A Windows event can be generated successfully while a particular Wazuh rule does not trigger.

Therefore, both the telemetry layer and the detection layer must be validated separately.

---

# 24. Investigation Findings

The investigation established the following findings.

### Finding 1 — PowerShell Script Block Logging was functioning

Windows generated Event ID 4104.

### Finding 2 — The actual PowerShell ScriptBlock was captured

The event contained the PowerShell command that performed the registry modification.

### Finding 3 — Wazuh successfully collected the event

The event became visible in the Wazuh Threat Hunting interface.

### Finding 4 — Wazuh Rule 91843 successfully triggered

The PowerShell registry modification was detected.

### Finding 5 — The Wazuh alert contained useful investigation data

The alert included:

* Agent information
* Windows Event ID
* PowerShell channel
* ScriptBlock content
* Detection rule
* Rule level
* MITRE ATT&CK mapping

### Finding 6 — The endpoint artifact was verified

The registry value was confirmed directly on the Windows endpoint.

---

# 25. Security Interpretation

This was an intentionally generated laboratory event.

The registry modification was created for detection testing.

Therefore, the activity itself should not be treated as malicious.

However, the telemetry is valuable from a SOC perspective.

In a real environment, PowerShell registry modification could require investigation depending on:

* The user account performing the action
* The process responsible for the activity
* The registry location
* The registry value
* The timing of the activity
* Whether the change was expected
* Other events occurring around the same time

The correct SOC approach is therefore to investigate the alert in context rather than automatically classify it as malicious.

---

# 26. Evidence Inventory

The Case 003 evidence consists of:

| Evidence                          | Purpose                                               |
| --------------------------------- | ----------------------------------------------------- |
| `PS_01_registry_test.png`         | Shows the controlled PowerShell registry test         |
| `PS_02_event_4104.png`            | Shows Windows Event ID 4104                           |
| `Wazuh_03_rule_91843.png`         | Shows the Wazuh detection                             |
| `Wazuh_04_alert_91843.png`        | Shows the detailed Wazuh alert                        |
| `Wazuh_04_alert_91843.json`       | Preserves the complete Wazuh alert as structured JSON |
| `PS_03_registry_verification.png` | Shows final endpoint verification                     |

---

# 27. Investigation Conclusion

The investigation successfully demonstrated the complete detection path from a controlled PowerShell action to a Wazuh alert.

The final chain was:

```text
PowerShell
    ↓
Script Block Logging
    ↓
Windows Event ID 4104
    ↓
Wazuh Agent
    ↓
Wazuh Manager
    ↓
Rule 91843
    ↓
Wazuh Alert
    ↓
Endpoint Verification
```

The activity was successfully identified by Wazuh as:

```text
Powershell executed "New-ItemProperty -Path".
Possible addition of new item to registry
```

The Wazuh alert was preserved as JSON evidence, while screenshots document the visual investigation process.

The registry artifact was also independently verified on the Windows endpoint.

---

# 28. Final Case Status

**Case 003 — Windows PowerShell Script Block Logging and Wazuh Detection**

```text
Status: COMPLETED
Detection: SUCCESSFUL
Windows Event ID: 4104
Wazuh Rule: 91843
```

The case demonstrates that the Windows endpoint can generate PowerShell ScriptBlock telemetry and that Wazuh can collect and detect the resulting activity.

---

# 29. Evidence References

### Visual Evidence

* PowerShell registry test
* Windows Event ID 4104
* Wazuh Rule 91843 detection
* Full Wazuh alert
* Final registry verification

### Structured Evidence

* Complete Wazuh Rule 91843 alert preserved as JSON

The evidence files are stored with this investigation so that the investigation can be reviewed without needing to reproduce the original activity.

````
