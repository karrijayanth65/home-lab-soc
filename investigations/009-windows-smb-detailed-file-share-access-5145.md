# Case 09 — Windows SMB Detailed File Share Access

> **Detection:** Wazuh Custom Rule `100145`  
> **Windows Event:** Security Event ID `5145` — Detailed File Share  
> **Severity:** Wazuh Level `8`  
> **Wazuh Agent:** `002` — `Windows11`  
> **Source:** Kali Linux `192.168.56.106`  
> **Destination:** Windows 11 `192.168.56.105` / `Jais_Lab_PC`  
> **Protocol:** SMB over TCP `445`  
> **Status:** **Detection Verified**  
> **Environment:** Controlled SOC laboratory

---

## 1. Investigation Overview

Case 09 follows a controlled SMB file-access operation from the Kali Linux test host to a Windows 11 SMB share and traces the activity through the complete defensive monitoring path.

The Windows endpoint was prepared with a controlled SMB share named `Case9-SMB`. The Kali test host then discovered the SMB service, validated that anonymous enumeration was denied, established authenticated access, located the controlled file `Case9-Test-Document.txt`, and read it through SMB.

That activity was visible at the network layer, recorded by Windows Security as Event ID `5145`, collected by Wazuh Agent `002`, and ultimately detected by custom Wazuh Rule `100145` as a Level `8` alert.

This was an intentional lab exercise. The evidence demonstrates detection capability and telemetry correlation; it does not represent a real-world compromise.

---

## 2. Architecture

The investigation begins with the client and follows the same path that the telemetry takes through the environment.

[![Case 09 — Windows SMB to Wazuh Detection Architecture](../architecture/Case%209%20SMB%20-%20Network%20Resource%20Access/ARCH_Case09_Windows_SMB_Wazuh_Detection_Architecture.png)](../architecture/Case%209%20SMB%20-%20Network%20Resource%20Access/ARCH_Case09_Windows_SMB_Wazuh_Detection_Architecture.png)

*Figure 1 — Case 09 detection architecture. Click the image to open the full repository artifact.*

```text
Kali Linux
192.168.56.106
      |
      | Authenticated SMB / TCP 445
      | Case9-Test-Document.txt
      v
Windows 11 / Jais_Lab_PC
192.168.56.105
      |
      | Security Event ID 5145
      v
Wazuh Agent 002
Windows11 / EventChannel
      |
      v
Wazuh Manager
Docker on Ubuntu
      |
      | Custom Rule 100145
      v
Wazuh Level 8 Alert
      |
      v
SOC Investigation
```

---

## 3. Preparing the Windows SMB Resource

The first part of the investigation establishes exactly what resource is being tested. The Windows endpoint contains the `Case9-SMB` network share, its permissions are documented, and the share is confirmed as the controlled resource used throughout the exercise.

[![PS_01 — Windows SMB Shares Baseline](../screenshots/Case%209/PS_01_Case9_Windows_SMB_Shares_Baseline.png)](../screenshots/Case%209/PS_01_Case9_Windows_SMB_Shares_Baseline.png)

*Figure 2 — Windows SMB shares baseline.*

The share permissions are then established for the controlled resource.

[![PS_02 — Windows SMB Share Permissions](../screenshots/Case%209/PS_02_Case9_Windows_SMB_Share_Permissions.png)](../screenshots/Case%209/PS_02_Case9_Windows_SMB_Share_Permissions.png)

*Figure 3 — Permissions associated with the Case 09 SMB share.*

The controlled share is created and made available for the test.

[![PS_03 — Windows SMB Share Created](../screenshots/Case%209/PS_03_Case9_Windows_SMB_Share_Created.png)](../screenshots/Case%209/PS_03_Case9_Windows_SMB_Share_Created.png)

*Figure 4 — Controlled `Case9-SMB` share.*

At this point, the Windows resource and its access configuration are established. The investigation can now move to the client attempting to reach it.

---

## 4. SMB Discovery and Access-Control Validation

The Kali Linux test host begins by identifying the SMB service exposed by the Windows endpoint.

[![PS_04 — Kali SMB Service Discovery](../screenshots/Case%209/PS_04_Case9_Kali_SMB_Service_Discovery.png)](../screenshots/Case%209/PS_04_Case9_Kali_SMB_Service_Discovery.png)

*Figure 5 — SMB service discovery from the Kali test host.*

The next step tests unauthenticated access. Anonymous enumeration is denied, establishing that the subsequent share interaction is performed through the intended authenticated path.

[![PS_05 — Kali SMB Anonymous Enumeration Denied](../screenshots/Case%209/PS_05_Case9_Kali_SMB_Anonymous_Enumeration_Denied.png)](../screenshots/Case%209/PS_05_Case9_Kali_SMB_Anonymous_Enumeration_Denied.png)

*Figure 6 — Anonymous SMB enumeration denied.*

With the unauthenticated path denied, the controlled test proceeds using authenticated SMB access.

---

## 5. Authenticated SMB Session

The Kali host establishes authenticated access to the `Case9-SMB` share.

[![PS_06 — Kali SMB Authenticated Share Access](../screenshots/Case%209/PS_06_Case9_Kali_SMB_Authenticated_Share_Access.png)](../screenshots/Case%209/PS_06_Case9_Kali_SMB_Authenticated_Share_Access.png)

*Figure 7 — Authenticated SMB share access from the Kali test host.*

The Windows endpoint independently confirms the resulting authenticated SMB session.

[![PS_07 — Windows SMB Authenticated Session](../screenshots/Case%209/PS_07_Case9_Windows_SMB_Authenticated_Session.png)](../screenshots/Case%209/PS_07_Case9_Windows_SMB_Authenticated_Session.png)

*Figure 8 — Windows-side confirmation of the authenticated SMB session.*

The client is now connected to the controlled share. The investigation next follows the specific file that will generate the detailed access telemetry.

---

## 6. Controlled File Access

A controlled document named `Case9-Test-Document.txt` is created in the SMB share.

[![PS_08 — Windows SMB Test File Created](../screenshots/Case%209/PS_08_Case9_Windows_SMB_Test_File_Created.png)](../screenshots/Case%209/PS_08_Case9_Windows_SMB_Test_File_Created.png)

*Figure 9 — Controlled test document used for Case 09.*

The authenticated Kali client discovers the document through the SMB share.

[![PS_09 — Kali SMB File Discovery](../screenshots/Case%209/PS_09_Case9_Kali_SMB_File_Discovery.png)](../screenshots/Case%209/PS_09_Case9_Kali_SMB_File_Discovery.png)

*Figure 10 — Discovery of `Case9-Test-Document.txt` through SMB.*

The client then performs the controlled read operation.

[![PS_10 — Kali SMB File Read](../screenshots/Case%209/PS_10_Case9_Kali_SMB_File_Read.png)](../screenshots/Case%209/PS_10_Case9_Kali_SMB_File_Read.png)

*Figure 11 — Controlled SMB file-read activity.*

This is the key activity that the Windows endpoint is expected to record. The next evidence establishes that the required Windows audit telemetry was enabled.

---

## 7. Enabling and Observing the Audit Telemetry

Windows SMB auditing is configured so that detailed file-share access can be recorded.

[![PS_12 — Windows SMB Audit Policy Enabled](../screenshots/Case%209/PS_12_Case9_Windows_SMB_Audit_Policy_Enabled.png)](../screenshots/Case%209/PS_12_Case9_Windows_SMB_Audit_Policy_Enabled.png)

*Figure 12 — Windows SMB audit policy configuration used for the detection.*

At the same time, the SMB exchange is independently visible on the network. The Wireshark capture shows the communication between the Kali client and Windows endpoint over TCP port `445`.

[![PS_13 — Wireshark SMB File Access](../screenshots/Case%209/PS_13_Case9_Wireshark_SMB_File_Access.png)](../screenshots/Case%209/PS_13_Case9_Wireshark_SMB_File_Access.png)

*Figure 13 — Wireshark evidence of the SMB file-access exchange.*

The observed network context includes:

```text
Source:       192.168.56.106
Destination:  192.168.56.105
Protocol:     SMB2
TCP port:     445
Target:       Case9-Test-Document.txt
Operations:   Create / GetInfo / Close
```

The network capture independently supports the activity already observed on the client side. The Windows Security log now provides the endpoint's authoritative record.

---

## 8. Windows Security Records Event ID 5145

Windows records the share-access check as Security Event ID `5145`, **Detailed File Share**.

[![PS_15 — Windows Security Event 5145 Source and Access](../screenshots/Case%209/PS_15_Case9_Windows_Security_5145_Source_and_Access.png)](../screenshots/Case%209/PS_15_Case9_Windows_Security_5145_Source_and_Access.png)

*Figure 14 — Windows Security Event ID 5145 showing source, share, target, and access information.*

The event provides the following investigation context:

```text
Log Name:             Security
Source:               Microsoft-Windows-Security-Auditing
Event ID:             5145
Task Category:        Detailed File Share
Level:                Information
Keywords:             Audit Success
Computer:             Jais_Lab_PC

Account Name:         Jais_test_PC
Account Domain:       Jais_Lab_PC

Source Address:       192.168.56.106
Source Port:          58812

Share Name:           \\*\Case9-SMB
Share Path:            \??\C:\SOC-Lab\Case9-SMB-Share
Relative Target Name: Case9-Test-Document.txt

Access Mask:          0x120089
```

The recorded access includes:

```text
READ_CONTROL
SYNCHRONIZE
ReadData (or ListDirectory)
ReadEA
ReadAttributes
```

This event connects the original SMB activity to an endpoint security record containing the source address, account, share, target file, and requested access.

---

## 9. Wazuh Detects the Event

The Windows Security event is collected through the Wazuh agent's EventChannel integration. Wazuh then evaluates the event against the Windows Security ruleset and the Case 09 custom rule.

The resulting alert is visible in the Wazuh Dashboard.

[![PS_16 — Wazuh Rule 100145 SMB 5145 Detection](../screenshots/Case%209/PS_16_Case9_Wazuh_Rule_100145_SMB_5145_Detection.png)](../screenshots/Case%209/PS_16_Case9_Wazuh_Rule_100145_SMB_5145_Detection.png)

*Figure 15 — Wazuh Level 8 detection generated by custom Rule `100145`.*

The final alert contains:

| Field | Value |
|---|---|
| Rule ID | `100145` |
| Rule Level | `8` |
| Description | `Case 09 - Windows Detailed File Share Access - Event ID 5145` |
| Agent | `Windows11` |
| Agent ID | `002` |
| Decoder | `windows_eventchannel` |
| Event ID | `5145` |
| Location | `EventChannel` |

The detection chain is now complete:

```text
Controlled SMB file access
        ↓
Network SMB telemetry
        ↓
Windows Security Event 5145
        ↓
Wazuh Agent 002
        ↓
Wazuh Custom Rule 100145
        ↓
Level 8 Wazuh alert
```

---

## 10. The Detection Rule

The alert is generated by the following custom Wazuh rule:

```xml
<group name="windows,smb,case9,">

  <rule id="100145" level="8">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^5145$</field>
    <description>Case 09 - Windows Detailed File Share Access - Event ID 5145</description>
    <group>network_share_access,windows_security,smb,</group>
  </rule>

</group>
```

The rule uses Windows Audit Success parent Rule `60103` and matches:

```text
win.system.eventID = 5145
```

The Wazuh manager configuration was validated with:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
```

The final validation returned:

```text
EXIT_CODE=0
```

The rule then successfully fired against the controlled Event ID `5145`.

---

## 11. What the SOC Analyst Can Determine

By following the evidence from beginning to end, the analyst can establish a consistent picture without relying on the Wazuh alert alone.

The activity originated from:

```text
192.168.56.106
```

It reached the Windows endpoint:

```text
192.168.56.105
Jais_Lab_PC
```

The activity used:

```text
SMB / TCP 445
```

The authenticated client accessed:

```text
Case9-SMB
```

The object involved was:

```text
Case9-Test-Document.txt
```

Windows recorded the access as:

```text
Security Event ID 5145
```

And Wazuh promoted the event to:

```text
Rule 100145
Level 8
```

This makes Event ID `5145` a useful investigation pivot. In production, the SOC should correlate the alert with authentication events, endpoint activity, source-host identity, account behavior, share sensitivity, and other network telemetry before determining whether the access is suspicious.

For this lab, the activity is intentionally generated and therefore classified as authorized laboratory activity.

---

## 12. Analyst Assessment

### Activity classification

**Authorized / Controlled Laboratory Activity**

The SMB access was deliberately generated using the known Kali test host, Windows endpoint, controlled account, controlled share, and test document.

### Detection assessment

**Detection Verified**

The evidence demonstrates that:

- the SMB activity occurred;
- network telemetry captured the SMB exchange;
- Windows generated Event ID `5145`;
- Wazuh received the Windows event;
- custom Rule `100145` matched the event; and
- Wazuh generated a Level `8` alert.

### Security interpretation

Event ID `5145` alone does not establish malicious intent or compromise. Its value is the detailed context it provides around a network-share access request.

In a production environment, a similar alert would warrant additional correlation when the source, account, share, target file, timing, or access pattern is unexpected.

---

## 13. Investigation Limitations

This case was executed in a controlled SOC laboratory.

Therefore:

- The SMB access was intentionally generated.
- The test account and test document were controlled lab resources.
- The evidence does not establish malicious intent.
- The evidence does not establish attacker attribution.
- Event ID `5145` by itself does not prove compromise.
- Rule `100145` covers the selected Event ID and is not a complete SMB threat-detection strategy.
- Production investigations should correlate the alert with authentication, endpoint, network, account, share, and file telemetry.

The defensible conclusion from this case is:

> **Controlled SMB network-share access was observed at the network layer, recorded by Windows Security Event ID `5145`, ingested by Wazuh, and detected through custom Rule `100145` at Level `8`.**

---

## 14. Supporting Documentation

The investigation is accompanied by two supporting documents.

The custom-rule document records the Wazuh rule creation and validation process, including the troubleshooting performed while getting Rule `100145` into a valid state.

The SOC alert document records the analyst-oriented interpretation of the resulting Level `8` Wazuh alert.

These are included in the attachment index below so the investigation itself remains focused on the evidence flow.

---

# 15. Evidence Attachments

The investigation above embeds each visual artifact at the point where it becomes relevant. This section provides the complete repository attachment list in one place for reviewers.

## Screenshots

1. [PS_01 — Windows SMB Shares Baseline](../screenshots/Case%209/PS_01_Case9_Windows_SMB_Shares_Baseline.png)
2. [PS_02 — Windows SMB Share Permissions](../screenshots/Case%209/PS_02_Case9_Windows_SMB_Share_Permissions.png)
3. [PS_03 — Windows SMB Share Created](../screenshots/Case%209/PS_03_Case9_Windows_SMB_Share_Created.png)
4. [PS_04 — Kali SMB Service Discovery](../screenshots/Case%209/PS_04_Case9_Kali_SMB_Service_Discovery.png)
5. [PS_05 — Kali SMB Anonymous Enumeration Denied](../screenshots/Case%209/PS_05_Case9_Kali_SMB_Anonymous_Enumeration_Denied.png)
6. [PS_06 — Kali SMB Authenticated Share Access](../screenshots/Case%209/PS_06_Case9_Kali_SMB_Authenticated_Share_Access.png)
7. [PS_07 — Windows SMB Authenticated Session](../screenshots/Case%209/PS_07_Case9_Windows_SMB_Authenticated_Session.png)
8. [PS_08 — Windows SMB Test File Created](../screenshots/Case%209/PS_08_Case9_Windows_SMB_Test_File_Created.png)
9. [PS_09 — Kali SMB File Discovery](../screenshots/Case%209/PS_09_Case9_Kali_SMB_File_Discovery.png)
10. [PS_10 — Kali SMB File Read](../screenshots/Case%209/PS_10_Case9_Kali_SMB_File_Read.png)
11. [PS_12 — Windows SMB Audit Policy Enabled](../screenshots/Case%209/PS_12_Case9_Windows_SMB_Audit_Policy_Enabled.png)
12. [PS_13 — Wireshark SMB File Access](../screenshots/Case%209/PS_13_Case9_Wireshark_SMB_File_Access.png)
13. [PS_15 — Windows Security Event 5145 Source and Access](../screenshots/Case%209/PS_15_Case9_Windows_Security_5145_Source_and_Access.png)
14. [PS_16 — Wazuh Rule 100145 SMB 5145 Detection](../screenshots/Case%209/PS_16_Case9_Wazuh_Rule_100145_SMB_5145_Detection.png)

## Architecture

[ARCH_Case09_Windows_SMB_Wazuh_Detection_Architecture.png](../architecture/Case%209%20SMB%20-%20Network%20Resource%20Access/ARCH_Case09_Windows_SMB_Wazuh_Detection_Architecture.png)

## Detection Engineering

[Case09_Wazuh_Custom_Rule_Creation.md](../scripts/Case%209%20SMB/Case09_Wazuh_Custom_Rule_Creation.md)

## SOC Reporting

[Case09_SOC_Alert_Documentation.docx](../docs/Case%209%20SMB/Case09_SOC_Alert_Documentation.docx)

---

# 16. Repository Structure

```text
home-lab-soc-1/
│
├── investigations/
│   └── 009-windows-smb-detailed-file-share-access-5145.md
│
├── architecture/
│   └── Case 9 SMB - Network Resource Access/
│       └── ARCH_Case09_Windows_SMB_Wazuh_Detection_Architecture.png
│
├── screenshots/
│   └── Case 9/
│       ├── PS_01_Case9_Windows_SMB_Shares_Baseline.png
│       ├── PS_02_Case9_Windows_SMB_Share_Permissions.png
│       ├── PS_03_Case9_Windows_SMB_Share_Created.png
│       ├── PS_04_Case9_Kali_SMB_Service_Discovery.png
│       ├── PS_05_Case9_Kali_SMB_Anonymous_Enumeration_Denied.png
│       ├── PS_06_Case9_Kali_SMB_Authenticated_Share_Access.png
│       ├── PS_07_Case9_Windows_SMB_Authenticated_Session.png
│       ├── PS_08_Case9_Windows_SMB_Test_File_Created.png
│       ├── PS_09_Case9_Kali_SMB_File_Discovery.png
│       ├── PS_10_Case9_Kali_SMB_File_Read.png
│       ├── PS_12_Case9_Windows_SMB_Audit_Policy_Enabled.png
│       ├── PS_13_Case9_Wireshark_SMB_File_Access.png
│       ├── PS_15_Case9_Windows_Security_5145_Source_and_Access.png
│       └── PS_16_Case9_Wazuh_Rule_100145_SMB_5145_Detection.png
│
├── scripts/
│   └── Case 9 SMB/
│       └── Case09_Wazuh_Custom_Rule_Creation.md
│
└── docs/
    └── Case 9 SMB/
        └── Case09_SOC_Alert_Documentation.docx
```

---

## Case Closure

**Case 09 — Windows SMB Detailed File Share Access — Rule `100145`: COMPLETE / DETECTION VERIFIED**

A controlled authenticated SMB file-share access from `192.168.56.106` to the Windows 11 endpoint was observed through network telemetry, recorded by Windows Security Event ID `5145`, forwarded through Wazuh Agent `002`, and successfully detected by custom Wazuh Rule `100145` at Level `8`.

The investigation preserves the complete path from the controlled activity to the final SOC alert, with the supporting screenshots embedded in sequence and the complete repository attachment list provided at the end.
