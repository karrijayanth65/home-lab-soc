Absolutely. Since this is going into your **GitHub portfolio**, let's make it look like a real SOC investigation report rather than just a lab note.

Copy-paste the entire content below into:

```text
investigations/001-windows-fim.md
```

````markdown
# Case 001 — Windows File Integrity Monitoring (FIM)

> **Lab Type:** Defensive Security / SIEM Detection  
> **Platform:** Wazuh  
> **Detection Capability:** File Integrity Monitoring (FIM)  
> **Endpoint:** Windows-10-Lab  
> **Status:** Completed  
> **Verdict:** Benign / Expected Activity

---

## 1. Executive Summary

This investigation validates the File Integrity Monitoring (FIM) capability of Wazuh using a controlled Windows 10 lab environment.

A dedicated directory was configured on the Windows endpoint:

```text
C:\SOC-Lab
````

Wazuh was configured to monitor this directory in real time.

A test file was then:

1. Created
2. Modified
3. Modified again

Wazuh successfully detected all three file-system events and generated alerts.

The investigation demonstrates how a SIEM/XDR platform can detect changes to monitored files, provide cryptographic hash information, identify the affected endpoint, and map certain detections to security frameworks such as MITRE ATT&CK.

Because all changes were intentionally performed by the lab administrator, the final analyst verdict is:

**BENIGN / EXPECTED ACTIVITY**

---

# 2. Investigation Objective

The objectives of this lab were to:

* Configure Windows File Integrity Monitoring.
* Monitor a controlled directory using Wazuh.
* Generate known file-system changes.
* Verify that Wazuh detects those changes in real time.
* Understand Wazuh FIM alerts and rule levels.
* Examine cryptographic hash changes.
* Understand the difference between an alert and a confirmed security incident.
* Analyze MITRE ATT&CK mappings.
* Practice SOC analyst investigation methodology.
* Document the investigation in a reproducible format.

---

# 3. Lab Architecture

The SOC lab currently consists of a Wazuh server running inside an Ubuntu virtual machine and a Windows 10 endpoint monitored by a Wazuh agent.

```text
                         SOC LAB
                           │
                     Host-only Network
                      192.168.56.0/24
                           │
             ┌─────────────┴─────────────┐
             │                           │
             ▼                           ▼
      Ubuntu Wazuh VM              Windows 10 VM
      192.168.56.103               192.168.56.104
             │                           │
             │                           │
      Docker Containers             Wazuh Agent
             │                           │
      ┌──────┼────────┐                  │
      │      │        │                  │
   Manager Indexer Dashboard             │
      │      │        │                  │
      └──────┴────────┴──────────────────┘
                    │
                    ▼
              Security Events
```

---

# 4. Environment Details

| Component           | Details                  |
| ------------------- | ------------------------ |
| Wazuh Server OS     | Ubuntu                   |
| Wazuh Deployment    | Docker                   |
| Wazuh Version       | 4.14.6                   |
| Wazuh Manager IP    | 192.168.56.103           |
| Windows Endpoint    | Windows-10-Lab           |
| Windows Agent ID    | 001                      |
| Windows IP          | 192.168.56.104           |
| Windows OS          | Microsoft Windows 10 Pro |
| Agent Group         | default                  |
| FIM Mode            | Real-time                |
| Monitored Directory | `C:\SOC-Lab`             |

---

# 5. Detection Technology

## File Integrity Monitoring

File Integrity Monitoring (FIM) is a security capability used to detect changes to files and directories.

A FIM system can identify events such as:

* File creation
* File modification
* File deletion
* File permission changes
* File ownership changes
* Cryptographic hash changes

This capability is useful because unauthorized modification of files can be an indicator of:

* Malware activity
* Configuration tampering
* Persistence
* Unauthorized administrative activity
* Data manipulation
* Security control modification

However, a FIM alert by itself does **not** prove that malicious activity occurred.

The alert must be investigated in context.

---

# 6. Wazuh FIM Configuration

A dedicated directory was selected for the experiment:

```text
C:\SOC-Lab
```

The directory was configured for real-time monitoring in the Windows Wazuh agent configuration file:

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

The following configuration was added inside the existing `<syscheck>` section:

```xml
<directories realtime="yes">C:\SOC-Lab</directories>
```

### Configuration explanation

```text
<directories>
```

Defines a directory that Wazuh should monitor.

```text
realtime="yes"
```

Enables real-time monitoring.

```text
C:\SOC-Lab
```

Defines the directory being monitored.

After modifying the configuration, the Wazuh agent service was restarted.

PowerShell command:

```powershell
Restart-Service WazuhSvc
```

The service status was then verified:

```powershell
Get-Service WazuhSvc
```

Result:

```text
Status   Name
------   ----
Running  WazuhSvc
```

This confirmed that the Wazuh agent was running with the updated configuration.

---

# 7. Test Methodology

A controlled file was created inside the monitored directory.

## Step 1 — Create the file

```powershell
New-Item -Path "C:\SOC-Lab\test-file.txt" -ItemType File
```

This created:

```text
C:\SOC-Lab\test-file.txt
```

The initial file size was:

```text
0 bytes
```

---

## Step 2 — Add content

The following command was executed:

```powershell
Set-Content -Path "C:\SOC-Lab\test-file.txt" -Value "SOC Lab - FIM test"
```

This changed the file from an empty file to a file containing test data.

---

## Step 3 — Modify the file again

The file was modified a second time:

```powershell
Add-Content -Path "C:\SOC-Lab\test-file.txt" -Value "Second modification"
```

This generated another integrity change.

---

# 8. Detection Results

Wazuh successfully detected three events.

| Event | Action   | Rule ID | Level | Description                |
| ----- | -------- | ------: | ----: | -------------------------- |
| 1     | Added    |     554 |     5 | File added to the system   |
| 2     | Modified |     550 |     7 | Integrity checksum changed |
| 3     | Modified |     550 |     7 | Integrity checksum changed |

Affected file:

```text
C:\SOC-Lab\test-file.txt
```

Affected endpoint:

```text
Windows-10-Lab
```

Agent:

```text
ID: 001
IP: 192.168.56.104
```

---

# 9. Event 1 — File Creation

Wazuh generated Rule 554:

```text
Rule ID: 554
Rule Level: 5
Description: File added to the system.
```

The event reported:

```text
File 'c:\soc-lab\test-file.txt' added
Mode: realtime
```

The file was initially empty.

Important initial values included:

```text
Size: 0 bytes
```

The empty-file hashes included:

```text
MD5:
d41d8cd98f00b204e9800998ecf8427e

SHA1:
da39a3ee5e6b4b0d3255bfef95601890afd80709

SHA256:
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

These values are consistent with an empty file.

### Analyst interpretation

The FIM system successfully detected the creation of a previously unknown file inside the monitored directory.

At this stage, the event only indicates:

> A file was created.

It does not indicate whether the file is malicious.

---

# 10. Event 2 — First File Modification

After content was added to the file, Wazuh generated Rule 550:

```text
Rule ID: 550
Rule Level: 7
Description: Integrity checksum changed.
```

Wazuh reported the following changed attributes:

```text
size
mtime
md5
sha1
sha256
```

The file size changed:

```text
0 bytes → 20 bytes
```

The MD5 hash changed:

```text
Before:
d41d8cd98f00b204e9800998ecf8427e

After:
00c4b09ed38a8dbb5b8ad8a976610671
```

The SHA1 hash changed:

```text
Before:
da39a3ee5e6b4b0d3255bfef95601890afd80709

After:
3e8284193cd8497891fb100d0f07983516d7a9b5
```

The SHA256 hash changed:

```text
Before:
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

After:
874ac7e9e9f8440e1e86e77093b65183d01f54eb1169045b263ccae5e03997c6
```

### Analyst interpretation

The change in file size and cryptographic hashes confirms that the file content changed.

This is stronger evidence than simply observing a modified timestamp.

---

# 11. Event 3 — Second File Modification

The file was modified again.

Wazuh generated another Rule 550 event.

The file size changed:

```text
20 bytes → 41 bytes
```

The following attributes changed again:

```text
size
mtime
md5
sha1
sha256
```

The SHA256 hash changed from:

```text
874ac7e9e9f8440e1e86e77093b65183d01f54eb1169045b263ccae5e03997c6
```

to:

```text
15e172faf20b49331a818ea663e68c9d7d98d1f49759536812a6b097dff73175
```

### Analyst interpretation

The second modification generated another integrity alert because the file's content and associated metadata changed.

This demonstrates that real-time FIM can detect repeated modifications rather than only the first change.

---

# 12. MITRE ATT&CK Mapping

Wazuh Rule 550 mapped the event to:

```text
MITRE ATT&CK Technique:
T1565.001 — Stored Data Manipulation

Tactic:
Impact
```

## Important analyst note

The presence of a MITRE ATT&CK mapping does **not** mean that an attack occurred.

The MITRE mapping describes a behavior that could be associated with a technique.

In this laboratory exercise:

```text
File modification
        ↓
Detected by FIM
        ↓
Rule 550
        ↓
Mapped to T1565.001
        ↓
But activity was intentionally generated
        ↓
BENIGN
```

This is an important SOC analyst lesson:

> **Detection ≠ confirmed compromise.**

---

# 13. Alert Severity Analysis

The events generated different rule levels.

### Rule 554

```text
Level: 5
Description:
File added to the system.
```

### Rule 550

```text
Level: 7
Description:
Integrity checksum changed.
```

A higher rule level indicates that Wazuh considers the event more significant, but severity should not be interpreted as proof of malicious behavior.

For example:

```text
Level 7 alert
        ↓
Investigate
        ↓
Who performed the action?
What file changed?
Where did it change?
When did it change?
Why did it change?
Was the activity authorized?
        ↓
Determine verdict
```

In this case, the analyst already knew that the changes were intentionally generated as part of the lab.

---

# 14. Investigation Timeline

```text
T1
File created
C:\SOC-Lab\test-file.txt
        │
        ▼
Wazuh Rule 554
Level 5
"File added to the system."

        │
        ▼

T2
File content added
        │
        ▼
Wazuh Rule 550
Level 7
"Integrity checksum changed."

        │
        ▼

T3
File modified again
        │
        ▼
Wazuh Rule 550
Level 7
"Integrity checksum changed."
```

---

# 15. Evidence Summary

| Evidence            | Observation                |
| ------------------- | -------------------------- |
| Endpoint            | Windows-10-Lab             |
| Agent ID            | 001                        |
| Endpoint IP         | 192.168.56.104             |
| File                | `C:\SOC-Lab\test-file.txt` |
| FIM mode            | realtime                   |
| File creation       | Detected                   |
| First modification  | Detected                   |
| Second modification | Detected                   |
| Rule 554            | Triggered                  |
| Rule 550            | Triggered twice            |
| Hash changes        | Detected                   |
| MITRE mapping       | T1565.001                  |
| Activity source     | Controlled lab activity    |
| Final verdict       | Benign                     |

---

# 16. Analyst Assessment

## Detection

**Successful**

Wazuh successfully detected:

* File creation
* File modification
* File integrity/hash changes
* Multiple consecutive modifications

---

## Investigation

The activity was intentionally generated by the SOC lab administrator.

The monitored directory was specifically created for testing:

```text
C:\SOC-Lab
```

The file was intentionally created and modified using PowerShell commands.

There was no evidence of unauthorized activity during this test.

---

# 17. Final Verdict

```text
VERDICT: BENIGN / EXPECTED ACTIVITY
```

### Reason

The activity was:

* Authorized
* Controlled
* Reproducible
* Generated intentionally
* Performed inside a dedicated SOC testing directory

Therefore, the Wazuh alerts represent **successful detection of expected laboratory activity**, not a confirmed security incident.

---

# 18. Security Significance

This experiment demonstrates how FIM can support a SOC analyst by providing visibility into changes that may otherwise go unnoticed.

For example, an attacker who modifies:

```text
System configuration
Security configuration
Application files
Startup files
Scripts
Sensitive documents
```

could potentially trigger FIM detections if those locations are appropriately monitored.

The analyst can then investigate:

```text
What changed?
Who changed it?
When did it change?
What was the previous hash?
What is the new hash?
Was the change authorized?
Does the activity correlate with other alerts?
```

FIM therefore provides an important source of endpoint telemetry.

---

# 19. Lessons Learned

### Lesson 1 — FIM is not the same as antivirus

FIM primarily detects changes to monitored files and directories.

It does not automatically determine whether the changed file is malicious.

---

### Lesson 2 — Alerts require investigation

A Level 7 alert should not automatically be treated as a confirmed compromise.

Context is critical.

---

### Lesson 3 — Hashes provide valuable evidence

Hash changes allow an analyst to demonstrate that the file's content changed.

Wazuh provided:

* MD5
* SHA1
* SHA256

before-and-after values.

---

### Lesson 4 — Real-time monitoring improves visibility

The `realtime="yes"` configuration allowed the changes to be detected shortly after they occurred.

---

### Lesson 5 — MITRE mappings provide context

The Wazuh alert mapped the behavior to:

```text
T1565.001 — Stored Data Manipulation
```

However, the mapping should be interpreted as behavioral context rather than proof of an attack.

---

### Lesson 6 — Controlled testing is important

Because the exact activity was known beforehand, we could compare:

```text
Expected behavior
        vs.
Observed telemetry
```

This is a useful methodology when validating security monitoring.

---

# 20. Detection Flow

```text
                 Windows 10
                     │
                     │
             File created/modified
                     │
                     ▼
              Wazuh Agent
                     │
               Syscheck/FIM
                     │
                     ▼
              Wazuh Manager
                     │
                     ▼
             Wazuh Indexer
                     │
                     ▼
             Wazuh Dashboard
                     │
                     ▼
                 Alert
                     │
                     ▼
             SOC Investigation
                     │
             ┌───────┴────────┐
             │                │
          Benign           Malicious
             │                │
             ▼                ▼
        Close case        Respond/
                          Investigate
```

---

# 21. Evidence to Preserve
* Wazuh FIM dashboard screenshot

<img width="1293" height="527" alt="Fim dash board" src="https://github.com/user-attachments/assets/7c72f009-2744-4c28-a5ef-6b378f6ca39d" />


* Wazuh event table screenshot

<img width="1351" height="417" alt="Wazuh FIM dashboard screenshot" src="https://github.com/user-attachments/assets/f281a448-a084-45a2-8304-d3b41d16c574" />

<img width="1357" height="191" alt="Wazuh event table screenshot" src="https://github.com/user-attachments/assets/b63cdf4c-7ed3-442a-b414-e1435713fe26" />
  
* JSON event data

<img width="1536" height="1024" alt="Json _1" src="https://github.com/user-attachments/assets/c9cec19c-9317-44aa-ae8c-7aae47d99070" />
  
* Windows FIM configuration

<img width="1242" height="318" alt="FIM adding" src="https://github.com/user-attachments/assets/b572258e-d6ac-41e9-b178-c94f4bbb0e84" />
  
* PowerShell test commands

<img width="719" height="380" alt="PowerShell test commands" src="https://github.com/user-attachments/assets/bf8c935d-ead5-4db5-8299-6dcb7d0a5a52" />

* Agent status

<img width="335" height="81" alt="Agent statsu" src="https://github.com/user-attachments/assets/eed5ff95-8719-45b9-99e4-3e6e220c3816" />
  
* Detection timestamps

Recommended screenshot location:

---

# 22. Reproduction Steps

To reproduce this experiment:

### Create monitored directory

```powershell
New-Item -Path "C:\SOC-Lab" -ItemType Directory -Force
```

### Configure Wazuh FIM

```xml
<directories realtime="yes">C:\SOC-Lab</directories>
```

### Restart Wazuh Agent

```powershell
Restart-Service WazuhSvc
```

### Verify service

```powershell
Get-Service WazuhSvc
```

Expected:

```text
Status   Name
------   ----
Running  WazuhSvc
```

### Create test file

```powershell
New-Item -Path "C:\SOC-Lab\test-file.txt" -ItemType File
```

### Add content

```powershell
Set-Content -Path "C:\SOC-Lab\test-file.txt" -Value "SOC Lab - FIM test"
```

### Modify again

```powershell
Add-Content -Path "C:\SOC-Lab\test-file.txt" -Value "Second modification"
```

### Verify detection

Navigate to:

```text
Wazuh Dashboard
    ↓
Endpoints
    ↓
Windows-10-Lab
    ↓
File Integrity Monitoring
    ↓
Events
```

Filter:

```text
agent.id: 001
rule.groups: syscheck
```

---

# 23. Detection Validation

| Requirement                     | Result |
| ------------------------------- | ------ |
| Windows agent connected         | PASS   |
| FIM configured                  | PASS   |
| Real-time monitoring enabled    | PASS   |
| File creation detected          | PASS   |
| File modification detected      | PASS   |
| Hash change detected            | PASS   |
| Multiple modifications detected | PASS   |
| Wazuh alert generated           | PASS   |
| MITRE mapping observed          | PASS   |
| Analyst investigation completed | PASS   |
| Final classification            | BENIGN |

---

# 24. Conclusion

The Windows File Integrity Monitoring experiment was successfully completed.

Wazuh detected the creation and subsequent modification of a monitored file in real time. The generated alerts contained useful forensic information including file path, timestamps, file size, ownership information, permissions, and cryptographic hashes.

The investigation also demonstrated an important SOC principle:

> **A security alert is a signal that requires investigation, not automatic proof of compromise.**

In this case, the activity was intentionally generated and therefore classified as:

```text
BENIGN / EXPECTED ACTIVITY
```

The successful detection validates the Wazuh FIM pipeline and provides a foundation for future investigations involving suspicious file modification, persistence, malware activity, and data manipulation.

---

# 25. Next Investigation

The next stage of the SOC lab will move beyond file integrity monitoring into **Windows security event monitoring**.

Planned areas include:

* Windows authentication events
* Failed login detection
* Successful authentication
* Account activity
* PowerShell activity
* Process execution
* Privilege-related events
* Suspicious command execution
* MITRE ATT&CK correlation

The ultimate objective is to generate controlled attack activity from the Kali Linux VM and investigate how Wazuh detects, correlates, and presents the resulting telemetry.

```text
FIM
 ↓
Windows Security Events
 ↓
Authentication Monitoring
 ↓
PowerShell / Process Telemetry
 ↓
Kali Attack Simulation
 ↓
Detection
 ↓
Investigation
 ↓
MITRE ATT&CK Mapping
 ↓
Incident Response
```

---

## Investigation Status

**Case 001 — CLOSED**

```text
Detection:       Successful
Investigation:   Completed
Classification:  Benign
Impact:          None
Response:        Not required
Lessons Learned: Documented
```

````

### One small GitHub tip

For this case, keep your **actual JSON event export** separate from this Markdown report. Don't dump the entire JSON into the report; it makes the case difficult to read.

A professional structure would eventually be:

```text
home-lab-soc-1/
├── investigations/
│   └── 001-windows-fim.md
│
├── screenshots/
│   └── case-001-windows-fim/
│       ├── 01-agent-active.png
│       ├── 02-fim-config.png
│       ├── 03-fim-dashboard.png
│       ├── 04-fim-events.png
│       └── 05-fim-event-details.png
│
└── ...
````

**Also:** don't commit raw logs containing passwords, API tokens, private keys, or other secrets. Your `.gitignore` foundation we created earlier should help protect those.
