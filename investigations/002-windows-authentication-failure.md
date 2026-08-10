# Case 002 — Windows Failed Authentication Detection

## 📌 Case Information

| Field            | Details                       |
| ---------------- | ----------------------------- |
| Case ID          | `002`                         |
| Investigation    | Windows Failed Authentication |
| Platform         | Windows 10                    |
| Endpoint         | `Windows-10-Lab`              |
| Agent ID         | `001`                         |
| Agent IP         | `192.168.56.104`              |
| SIEM/XDR         | Wazuh 4.14.6                  |
| Detection Rule   | `60122`                       |
| Alert Level      | `5`                           |
| Windows Event ID | `4625`                        |
| Status           | **Completed**                 |
| Environment      | Isolated SOC Home Lab         |

---

## 🎯 Objective

The objective of this investigation was to validate that Wazuh can:

1. Collect Windows Security events.
2. Detect failed authentication attempts.
3. Generate a corresponding Wazuh alert.
4. Provide useful authentication evidence to a SOC analyst.
5. Allow the analyst to investigate the event from the Wazuh Dashboard.

This was a controlled test performed entirely inside the isolated SOC laboratory environment.

---

# 🧪 Lab Environment

The test was performed using the existing SOC lab infrastructure.

```text
┌─────────────────────────────┐
│        Windows 10 VM        │
│                             │
│  Windows-10-Lab             │
│  IP: 192.168.56.104         │
│                             │
│  Wazuh Agent                │
└──────────────┬──────────────┘
               │
               │ Security Events
               │
               ▼
┌─────────────────────────────┐
│      Ubuntu Wazuh Server    │
│                             │
│  Wazuh Manager              │
│  Wazuh Indexer              │
│  Wazuh Dashboard            │
│                             │
│  IP: 192.168.56.103         │
└─────────────────────────────┘
```

---

# 👤 Test Account

A dedicated local account was created for authentication testing:

```text
Username: SOC-TestUser
Enabled:  True
Purpose:  SOC Lab authentication testing
```

The account was created specifically so that authentication activity could be generated without using a normal personal account.

> **Security note:** Credentials are intentionally excluded from this documentation.

---

# 🔬 Test Procedure

## Step 1 — Verify the Wazuh Agent

The Windows Wazuh service was verified using:

```powershell
Get-Service WazuhSvc
```

Expected state:

```text
Status: Running
Name:   WazuhSvc
```

This confirmed that the Wazuh agent was operational before testing.

---

## Step 2 — Verify Windows Security Event Collection

The Wazuh agent configuration was checked to confirm that the Windows Security event channel was being collected.

Relevant configuration:

```xml
<localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
</localfile>
```

The Wazuh agent log also showed:

```text
Analyzing event log: 'Security'
```

This confirmed that Wazuh was actively monitoring the Windows Security event channel.

---

# Step 3 — Generate Controlled Authentication Failure

A deliberately incorrect password was supplied for the test account:

```text
SOC-TestUser
```

The authentication attempt was rejected by Windows.

The resulting Windows error indicated:

```text
The user name or password is incorrect.
```

This was intentional and performed only against the lab Windows VM.

---

# Step 4 — Validate Windows Event ID 4625

Windows generated:

```text
Event ID: 4625
Provider: Microsoft-Windows-Security-Auditing
```

Event 4625 represents a failed account logon.

The Windows event contained:

```text
Account For Which Logon Failed:
    Account Name: SOC-TestUser

Failure Reason:
    Unknown user name or bad password.

Status:
    0xC000006D

Sub Status:
    0xC000006A
```

This confirmed that Windows recorded the failed authentication at the operating-system level.

---

# Step 5 — Verify Wazuh Detection

The Wazuh Dashboard was opened:

```text
Threat Hunting → Events
```

The following query was used:

```text
agent.id:001 AND data.win.system.eventID:4625
```

The time range was restricted to:

```text
Last 15 minutes
```

Wazuh returned fresh authentication alerts.

### Observed results

```text
Rule ID:     60122
Level:       5
Description: Logon Failure - Unknown user or bad password
```

Two fresh events were observed.

---

# 🚨 Detection Details

## Wazuh Rule

```text
Rule ID: 60122
Level:   5
```

Description:

```text
Logon Failure - Unknown user or bad password
```

Rule groups:

```text
windows
windows_security
authentication_failed
```

This confirms that Wazuh successfully interpreted the Windows Security event and classified it as an authentication failure.

---

# 🔍 Evidence Analysis

The Wazuh event contained the following important fields.

| Evidence               | Observed Value                        |
| ---------------------- | ------------------------------------- |
| Agent Name             | `Windows-10-Lab`                      |
| Agent ID               | `001`                                 |
| Agent IP               | `192.168.56.104`                      |
| Windows Event ID       | `4625`                                |
| Channel                | `Security`                            |
| Provider               | `Microsoft-Windows-Security-Auditing` |
| Target Account         | `SOC-TestUser`                        |
| Target Computer        | `DESKTOP-9IT05P4`                     |
| Logon Type             | `2`                                   |
| Failure Reason         | Unknown user name or bad password     |
| Status                 | `0xC000006D`                          |
| Sub-status             | `0xC000006A`                          |
| Source Address         | `::1`                                 |
| Authentication Package | `Negotiate`                           |
| Process                | `C:\Windows\System32\svchost.exe`     |
| Wazuh Rule             | `60122`                               |
| Wazuh Level            | `5`                                   |

---

# 🧠 SOC Analyst Interpretation

## What happened?

A login attempt was made against the local Windows endpoint using the test account:

```text
SOC-TestUser
```

The supplied credentials were incorrect.

Windows rejected the authentication request and generated:

```text
Event ID 4625
```

Wazuh collected the event through the Windows EventChannel integration and generated:

```text
Rule 60122
```

---

## 👤 Who was targeted?

The target account was:

```text
SOC-TestUser
```

This is identified by:

```text
targetUserName
```

This distinction is important because the **subject account** and **target account** are not necessarily the same.

Observed:

```text
Subject:
Windows Lab

Target:
SOC-TestUser
```

---

## 💻 Which endpoint was involved?

The affected endpoint was:

```text
Windows-10-Lab
```

with IP:

```text
192.168.56.104
```

Hostname:

```text
DESKTOP-9IT05P4
```

---

## 🌐 Was this a remote attack?

No.

The event contained:

```text
ipAddress: ::1
```

`::1` represents the IPv6 loopback address.

Therefore, this particular authentication test originated locally on the Windows machine.

This is an important distinction.

### Current case

```text
Windows
   │
   ├── Local authentication attempt
   │
   └── Wrong password
          ↓
       Event 4625
          ↓
       Wazuh
```

### Not yet demonstrated

```text
Kali
   │
   │ Remote authentication attempt
   ▼
Windows
   │
   ▼
Event 4625
   │
   ▼
Wazuh
```

The remote attack scenario will be investigated separately.

---

# 🔢 Logon Type Analysis

The event contained:

```text
logonType: 2
```

This represents an **interactive logon**.

This is useful contextual information for a SOC analyst because different authentication scenarios can produce different logon types.

Therefore, an analyst should not investigate only:

```text
Event ID = 4625
```

but should correlate it with:

```text
Event ID
+
Target Account
+
Logon Type
+
Source Address
+
Failure Reason
+
Process
```

---

# 🔐 Authentication Failure Analysis

The event contained:

```text
Status:
0xC000006D
```

and:

```text
Sub Status:
0xC000006A
```

The event message identified the failure as:

```text
Unknown user name or bad password.
```

This provides strong evidence that the authentication attempt failed because the supplied credentials were invalid.

---

# 📊 Detection Flow

The complete telemetry path was successfully validated:

```text
┌───────────────────────────┐
│       Windows 10          │
│                           │
│ Authentication attempt    │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│ Windows Security Log      │
│                           │
│ Event ID 4625             │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│ Wazuh Agent               │
│                           │
│ Windows EventChannel      │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│ Wazuh Manager             │
│                           │
│ Rule 60122                │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│ Wazuh Dashboard           │
│                           │
│ Level 5 Alert             │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│ SOC Analyst               │
│                           │
│ Investigate & Respond     │
└───────────────────────────┘
```

---

# 🛡️ MITRE ATT&CK Context

Wazuh associated this alert with:

```text
Technique: Account Access Removal
Technique ID: T1531
Tactic: Impact
```

However, for this controlled lab event, the primary activity we observed was simply a **failed authentication attempt**.

The MITRE mapping is Wazuh's rule metadata and should be interpreted in the context of the actual evidence rather than assuming that the technique itself occurred maliciously.

---

# 🧪 Investigation Assessment

### Detection

```text
SUCCESS
```

### Windows telemetry

```text
SUCCESS
```

### Wazuh Agent collection

```text
SUCCESS
```

### Wazuh Manager processing

```text
SUCCESS
```

### Wazuh Dashboard visibility

```text
SUCCESS
```

### Authentication evidence

```text
SUCCESS
```

### Remote attack simulation

```text
NOT PERFORMED IN THIS CASE
```

---

# 💡 Lessons Learned

This investigation demonstrated several important SOC concepts:

1. Windows records authentication failures as Security Event ID `4625`.
2. Wazuh can collect Windows Security events through EventChannel.
3. Wazuh rule `60122` detects failed Windows logons.
4. Event details are more valuable than the alert title alone.
5. `targetUserName` identifies the account being authenticated.
6. `logonType` provides authentication context.
7. `ipAddress` helps determine whether an authentication attempt was local or remote.
8. Authentication status and sub-status codes provide additional evidence.
9. A single failed login does not automatically indicate a compromise.
10. Multiple authentication failures can provide stronger evidence of brute-force activity.

---

# 📸 Evidence / Screenshots

The following screenshots were captured during the investigation:

```text
screenshots/
└── Case 2/
    ├── Test user created.png
    ├── Test user created_1.png
    ├── Win_event_1.png
    ├── Win_event_2.png
    ├── Win_event_3.png
    ├── Wazuh_TH_Query.png
    ├── Fresh_wrong_hits.png
    └── Results_TH.png
```

### Evidence purpose

| Screenshot                | Purpose                                                          |
| ------------------------- | ---------------------------------------------------------------- |
| `Test user created.png`   | Demonstrates creation/verification of the dedicated test account |
| `Test user created_1.png` | Supporting account/testing evidence                              |
| `Win_event_1.png`         | Windows authentication event evidence                            |
| `Win_event_2.png`         | Windows Event 4625 details                                       |
| `Win_event_3.png`         | Additional Windows event evidence                                |
| `Wazuh_TH_Query.png`      | Wazuh Threat Hunting query                                       |
| `Fresh_wrong_hits.png`    | Fresh Wazuh detections for Event ID 4625                         |
| `Results_TH.png`          | Wazuh investigation results                                      |

> Screenshots are retained as visual evidence of the investigation workflow and validation steps.

---

# 📝 Analyst Conclusion

The controlled authentication test was successfully detected from end to end.

Windows generated Security Event ID `4625` after an invalid authentication attempt against the `SOC-TestUser` account. The Wazuh agent collected the event through the Windows Security EventChannel, the Wazuh manager processed the event, and rule `60122` generated a Level 5 authentication-failure alert.

The event originated from the Windows system itself (`::1` loopback address), so this investigation should **not** be classified as a remote attack.

The detection pipeline is confirmed operational and ready for the next phase of testing.

---
