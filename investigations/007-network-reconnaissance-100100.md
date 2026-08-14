# 🔴 PHASE 2 --- Attacker → Victim → Defender

# Case 07 --- Network Reconnaissance

> **Status:** ✅ VALIDATED / READY FOR CASE CLOSURE\
> **Phase:** Phase 2 --- Attacker → Victim → Defender\
> **Case focus:** Network Reconnaissance\
> **Primary attacker platform:** Kali Linux\
> **Primary victim:** Windows 11\
> **Defender/SIEM:** Wazuh\
> **Network visibility:** Wireshark
>
> This investigation is intentionally written from the defender's
> perspective: what the attacker can discover, what the victim observes,
> what the network observes, what Wazuh observes, and where visibility
> remains incomplete.

------------------------------------------------------------------------

## 1. Case Objective

Case 07 investigates **network reconnaissance** from an attacker →
victim → defender perspective.

The goal is not simply to prove that a port was blocked. The goal is to
understand the complete observation chain:

``` text
Kali attacker
    ↓
Network reconnaissance / connection attempt
    ↓
Windows 11 victim
    ↓
Windows Firewall / pfirewall.log
    ↓
Wazuh Agent 002
    ↓
Wazuh Manager
    ↓
Wazuh decoder + detection rule
    ↓
Wazuh Dashboard
```

### Questions this case answers

1.  **What can an attacker discover?**
2.  **What does the victim observe?**
3.  **What does the network observe?**
4.  **What does Wazuh observe?**
5.  **What evidence is missing?**

------------------------------------------------------------------------

# 2. Lab Participants

  ------------------------------------------------------------------------
  Role              System            Address /          Purpose
                                      Identifier         
  ----------------- ----------------- ------------------ -----------------
  Attacker          Kali Linux        `192.168.56.106`   Controlled
                                                         reconnaissance
                                                         source

  Victim            Windows 11        `192.168.56.105`   Reconnaissance
                                                         target

  Wazuh agent       Windows 11        Agent `002`        Endpoint
                                                         telemetry
                                                         collection

  Wazuh manager     Ubuntu / Docker   Wazuh manager      SIEM processing
                                                         and alerting

  Network sensor    Wireshark         Host-only lab      Network-level
                                      interface          visibility
  ------------------------------------------------------------------------

------------------------------------------------------------------------

# 3. Case Scope

The investigation concentrates on reconnaissance involving **TCP/445
(Microsoft-DS / SMB)**.

The observed test result from Kali was:

``` text
445/tcp filtered
```

This indicates that the target was reachable enough for Nmap to classify
the port, but the connection was being filtered rather than presented as
an openly accessible service.

The Windows firewall subsequently recorded real TCP DROP events
involving:

``` text
Source:      192.168.56.106
Destination: 192.168.56.105
Protocol:    TCP
Destination: 445
Action:      DROP
```

------------------------------------------------------------------------

# 4. Evidence Layout

This Markdown file is located at:

``` text
SOC-Lab/
└── home-lab-soc-1/
    └── investigations/
        └── Case_07_Network_Reconnaissance.md
```

The screenshots are expected at:

``` text
SOC-Lab/
└── home-lab-soc-1/
    └── screenshots/
        └── Case 07/
```

Therefore the embedded image paths in this document use:

``` text
../screenshots/Case%207/
```

No screenshot is intentionally copied into the `investigations`
directory. The investigation document references the original evidence
files.

------------------------------------------------------------------------

# 5. Evidence Index

  -----------------------------------------------------------------------------------------------------------------------------------------------
  Evidence                                                                                  Purpose           Investigation     Importance
                                                                                                              layer             
  ----------------------------------------------------------------------------------------- ----------------- ----------------- -----------------
  [PS_01](../screenshots/Case%207/PS_01_Case7_Windows11_Network_Baseline.png)               Windows network   Victim            Supporting
                                                                                            baseline                            

  [PS_02](../screenshots/Case%207/PS_02_Case7_Sysmon_Baseline.png)                          Sysmon baseline   Victim            Supporting

  [PS_03](../screenshots/Case%207/PS_03_Case7_Kali_Network_Topology.png)                    Kali network      Attacker /        Supporting
                                                                                            topology          Network           

  [PS_04](../screenshots/Case%207/PS_04_Case7_Kali_Windows11_ARP_Connectivity.png)          Kali ↔ Windows    Network           Supporting
                                                                                            connectivity                        

  [PS_05](../screenshots/Case%207/PS_05_Case7_Wireshark_HostOnly_Baseline.png)              Host-only traffic Network           Supporting
                                                                                            baseline                            

  [PS_06](../screenshots/Case%207/PS_06_Case7_Wireshark_ARP_Learning.png)                   ARP learning      Network           Supporting

  [PS_07](../screenshots/Case%207/PS_07_Case7_Nmap_TCP_Recon_Result.png)                    TCP               Attacker          **Key**
                                                                                            reconnaissance /                    
                                                                                            port result                         

  [PS_08](../screenshots/Case%207/PS_08_Case7_Wireshark_TCP_Recon_Evidence.png)             TCP               Network           **Key**
                                                                                            reconnaissance                      
                                                                                            traffic                             

  [PS_09](../screenshots/Case%207/PS_09_Case7_Windows_Firewall_Profile_Logging.png)         Firewall          Victim            Supporting
                                                                                            profile/logging                     
                                                                                            configuration                       

  [PS_09b](../screenshots/Case%207/PS_09_Case7_Windows_LocalPorts.png)                      Windows local     Victim            Supporting
                                                                                            ports                               

  [PS_10](../screenshots/Case%207/PS_10_Case7_Windows_Firewall_Profile_Logging.png)         Firewall logging  Victim            Supporting
                                                                                            state                               

  [PS_11](../screenshots/Case%207/PS_11_Case7_Windows_Firewall_BlockLogging_Enabled.png)    Windows firewall  Victim            **Key**
                                                                                            blocked-event                       
                                                                                            evidence                            

  [PS_11-W](../screenshots/Case%207/PS_11_Case7_Wazuh_Firewall_DROP_Alert.png)              Wazuh Dashboard   Defender / SIEM   **Key**
                                                                                            detection                           

  [PS_12-W](../screenshots/Case%207/PS_12_Case7_Wazuh_Firewall_DROP_Document_Details.png)   Normalized Wazuh  Defender / SIEM   **Key**
                                                                                            event details                       

  [PS_12-N](../screenshots/Case%207/PS_12_Case7_Wireshark_Recon_AfterFirewallLogging.png)   Recon traffic     Network           Supporting
                                                                                            corroboration                       

  [PS_14](../screenshots/Case%207/PS_14_Case7_Windows_Firewall_Log_Recon_Drops.png)         Windows firewall  Victim            **Key**
                                                                                            DROP records                        

  [PS_15](../screenshots/Case%207/PS_15_Case7_Wazuh_Manager_Raw_Firewall_Ingestion.png)     Manager-side      Defender / SIEM   Supporting
                                                                                            firewall                            
                                                                                            ingestion                           
  -----------------------------------------------------------------------------------------------------------------------------------------------

> **Evidence policy:** The key evidence is deliberately kept small.
> Baseline and supporting captures are retained for context, but the
> case does not require every screenshot to be cited as primary proof.

------------------------------------------------------------------------

# 6. Phase A --- Attacker Perspective

## 6.1 Attacker Setup

Kali Linux was used as the controlled attacker/reconnaissance platform.

The relevant source address observed in the final firewall telemetry
was:

``` text
192.168.56.106
```

The Windows victim was:

``` text
192.168.56.105
```

### Network context

![Kali network
topology](../screenshots/Case%207/PS_03_Case7_Kali_Network_Topology.png)

![Kali ↔ Windows
connectivity](../screenshots/Case%207/PS_04_Case7_Kali_Windows11_ARP_Connectivity.png)

------------------------------------------------------------------------

## 6.2 What Can the Attacker Discover?

Network reconnaissance allows an attacker to learn information about the
target's reachable attack surface.

For this case, the important discovery target was:

``` text
TCP/445
```

The Nmap result showed:

``` text
445/tcp filtered
```

with the service associated with:

``` text
microsoft-ds
```

### Attacker-side evidence

![Nmap TCP reconnaissance
result](../screenshots/Case%207/PS_07_Case7_Nmap_TCP_Recon_Result.png)

The important defender interpretation is:

> The attacker can determine that TCP/445 exists as a network-visible
> target and that the connection is being filtered rather than simply
> appearing as an open service.

The reconnaissance result alone does **not** reveal why the port is
filtered. That requires victim-side or network-side telemetry.

------------------------------------------------------------------------

# 7. Phase B --- Network Perspective

## 7.1 What Does the Network Observe?

Wireshark provides visibility at the network level.

The captures establish the host-only network environment and provide
corroborating evidence for reconnaissance activity.

### Baseline

![Wireshark ARP
learning](../screenshots/Case%207/PS_05_Case7_Wireshark_HostOnly_Baseline.png)

### ARP learning

![Wireshark ARP
learning](../screenshots/Case%207/PS_06_Case7_Wireshark_ARP_Learning.png)

### TCP reconnaissance

![Wireshark TCP
reconnaissance](../screenshots/Case%207/PS_08_Case7_Wireshark_TCP_Recon_Evidence.png)

### Reconnaissance after firewall logging

![Wireshark reconnaissance after firewall
logging](../screenshots/Case%207/PS_12_Case7_Wireshark_Recon_AfterFirewallLogging.png)

### Network interpretation

Wireshark can show that network activity occurred between the attacker
and victim.

However, network traffic alone may not tell the SOC:

-   which host firewall policy made the decision,
-   which local firewall profile was active,
-   whether the connection was intentionally blocked,
-   or which SIEM detection rule should represent the event.

That is why network telemetry is combined with endpoint and SIEM
telemetry.

------------------------------------------------------------------------

# 8. Phase C --- Victim Perspective

## 8.1 What Does Windows Observe?

Windows Firewall logging was enabled and the relevant firewall log was:

``` text
C:\WINDOWS\System32\LogFiles\Firewall\pfirewall.log
```

The firewall recorded DROP events involving the reconnaissance source.

A representative observed event was:

``` text
2026-08-14 20:05:57 DROP TCP 192.168.56.106 192.168.56.105 46366 445 44 S 2659184373 0 1024 - - - RECEIVE 4
```

A second observed event used source port `46368`:

``` text
2026-08-14 20:05:57 DROP TCP 192.168.56.106 192.168.56.105 46368 445 44 S 2659053303 0 1024 - - - RECEIVE 4
```

The important fields are:

``` text
Action:       DROP
Protocol:     TCP
Source IP:    192.168.56.106
Destination:  192.168.56.105
Destination:  445
```

------------------------------------------------------------------------

## 8.2 Windows Firewall Evidence

![Windows Firewall profile and
logging](../screenshots/Case%207/PS_09_Case7_Windows_Firewall_Profile_Logging.png)

![Windows local
ports](../screenshots/Case%207/PS_09_Case7_Windows_LocalPorts.png)

![Windows Firewall
logging](../screenshots/Case%207/PS_10_Case7_Windows_Firewall_Profile_Logging.png)

![Windows Firewall blocked-event
evidence](../screenshots/Case%207/PS_11_Case7_Windows_Firewall_BlockLogging_Enabled.png)

![Windows Firewall DROP
records](../screenshots/Case%207/PS_14_Case7_Windows_Firewall_Log_Recon_Drops.png)

### Victim interpretation

The Windows endpoint provides information that the attacker-side Nmap
result cannot provide by itself:

> The connection attempt to TCP/445 was actually processed by the
> Windows Firewall and recorded as `DROP`.

This establishes the victim-side explanation for the `filtered` Nmap
result.

------------------------------------------------------------------------

# 9. Phase D --- Wazuh Perspective

## 9.1 What Does Wazuh Observe?

Wazuh receives and processes the Windows firewall telemetry.

The final normalized event contained:

  Field              Value
  ------------------ -------------------------------------------------------
  Agent ID           `002`
  Agent name         `Windows11`
  Agent IP           `192.168.56.105`
  Action             `DROP`
  Protocol           `TCP`
  Source IP          `192.168.56.106`
  Source port        `46366` / `46368`
  Destination IP     `192.168.56.105`
  Destination port   `445`
  Decoder            `windows-firewall`
  Rule               `100100`
  Alert level        `7`
  Location           `C:\WINDOWS\System32\LogFiles\Firewall\pfirewall.log`

------------------------------------------------------------------------

## 9.2 Wazuh Decoder Validation

The final decoder processing successfully extracted:

``` text
action:   DROP
protocol: TCP
srcip:    192.168.56.106
srcport:  58742
dstip:    192.168.56.105
dstport:  445
```

This demonstrated that the firewall event could be normalized into
structured fields.

------------------------------------------------------------------------

## 9.3 Wazuh Rule Processing

The built-in firewall rule:

``` text
4101
```

matched:

``` text
action = DROP
```

and classified the event as:

``` text
Firewall drop event.
```

For Case 07, a local rule was used to make the detection explicitly
visible as a case-level alert:

``` text
Rule ID: 100100
Level:   7

Description:
Windows Firewall DROP event - logged for Case 7.
```

Groups:

``` text
local
firewall
firewall_drop
network_recon
```

------------------------------------------------------------------------

# 10. Wazuh Dashboard Evidence

The Wazuh Dashboard was queried using:

``` text
agent.id:002 AND rule.id:100100
```

The dashboard returned:

``` text
2 hits
```

This confirms that the reconnaissance-related firewall events were
visible as SIEM alerts.

![Wazuh Firewall DROP
Alert](../screenshots/Case%207/PS_11_Case7_Wazuh_Firewall_DROP_Alert.png)

------------------------------------------------------------------------

# 11. Wazuh Document Details

The Document Details view provides the strongest normalized-event
evidence.

The observed event contained:

``` text
agent.id:       002
agent.name:     Windows11
agent.ip:       192.168.56.105

data.action:    DROP
data.protocol:  TCP
data.srcip:     192.168.56.106
data.srcport:   46368
data.dstip:     192.168.56.105
data.dstport:   445

decoder.name:   windows-firewall

rule.id:        100100
rule.level:     7
rule.firedtimes: 2
```

The location was:

``` text
C:\WINDOWS\System32\LogFiles\Firewall\pfirewall.log
```

![Wazuh Firewall DROP Document
Details](../screenshots/Case%207/PS_12_Case7_Wazuh_Firewall_DROP_Document_Details.png)

This is the strongest single technical evidence because it connects:

``` text
Attacker IP
    +
Victim IP
    +
Protocol
    +
Port
    +
DROP decision
    +
Wazuh rule
    +
Wazuh severity
    +
Windows firewall log location
```

------------------------------------------------------------------------

# 12. Manager-Side Ingestion

Manager-side evidence was retained during the investigation to verify
the Wazuh processing path.

![Wazuh Manager raw firewall
ingestion](../screenshots/Case%207/PS_15_Case7_Wazuh_Manager_Raw_Firewall_Ingestion.png)

The manager-side evidence is supporting evidence. The final alert and
Document Details views are preferred for the primary SIEM proof.

------------------------------------------------------------------------

# 13. Investigation Timeline

  -----------------------------------------------------------------------
  Stage                   Observation             Result
  ----------------------- ----------------------- -----------------------
  1                       Lab baseline            Environment known
                          established             

  2                       Kali → Windows          Network path confirmed
                          connectivity validated  

  3                       TCP/445 reconnaissance  Port classified as
                          performed               filtered

  4                       Wireshark captured      Network telemetry
                          network activity        available

  5                       Windows Firewall        Endpoint telemetry
                          logging verified        available

  6                       Windows recorded        Victim-side decision
                          TCP/445 DROP            confirmed

  7                       Wazuh received firewall SIEM collection
                          telemetry               confirmed

  8                       Initial decoder failed  Blind spot identified

  9                       Controlled decoder      Fields isolated and
                          testing performed       validated

  10                      Final decoder matched   Full event decoded

  11                      Built-in rule 4101      Firewall DROP
                          matched                 classification
                                                  confirmed

  12                      Local rule 100100 fired Level-7 case alert
                                                  created

  13                      `alerts.json` confirmed Alert persistence
                          alert                   confirmed

  14                      Dashboard returned 2    SIEM visibility
                          hits                    confirmed

  15                      Document Details        End-to-end case proof
                          verified fields         complete
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# 14. Troubleshooting: What Was the Blind Spot?

The initial problem was **not**:

-   Kali connectivity
-   Windows Firewall
-   Windows logging
-   Wazuh Agent connectivity
-   Wazuh Manager availability
-   analysisd firewall processing
-   the existence of TCP/445 traffic

The investigation proved that the firewall event was already present.

The initial blind spot was the **assumed event format used by the first
custom decoder**.

The troubleshooting process therefore used controlled isolation:

``` text
1. Confirm event exists
       ↓
2. Confirm Wazuh receives it
       ↓
3. Test decoder
       ↓
4. Extract fields individually
       ↓
5. Compare with built-in Wazuh decoder
       ↓
6. Correct decoder representation
       ↓
7. Validate Phase 2
       ↓
8. Validate Phase 3
       ↓
9. Validate real alert
       ↓
10. Validate Dashboard
```

This was important because changing several Wazuh components
simultaneously would have made the root cause harder to identify.

------------------------------------------------------------------------

# 15. Attacker → Victim → Defender Analysis

## 15.1 Attacker --- What Can Be Discovered?

The attacker can discover:

-   that the target is reachable,
-   that TCP/445 is a network-visible port,
-   that the port is not openly available,
-   and that filtering is occurring.

The Nmap result alone does **not** prove that Windows Firewall caused
the filtering.

------------------------------------------------------------------------

## 15.2 Victim --- What Does Windows Observe?

Windows provides stronger local context:

``` text
DROP TCP
192.168.56.106
        →
192.168.56.105:445
```

The Windows firewall log therefore explains the victim-side enforcement
decision.

------------------------------------------------------------------------

## 15.3 Network --- What Does Wireshark Observe?

Wireshark provides packet-level/network-level visibility.

It can corroborate that communication attempts occurred between the two
lab systems.

However, packet visibility alone does not necessarily provide the
endpoint's firewall decision or SIEM classification.

------------------------------------------------------------------------

## 15.4 Defender --- What Does Wazuh Observe?

Wazuh combines endpoint telemetry and detection logic.

The final alert gives the SOC analyst:

``` text
Who?
192.168.56.106

Target?
192.168.56.105

Protocol?
TCP

Target port?
445

Action?
DROP

Which endpoint?
Windows11 / Agent 002

Which detection?
Rule 100100

Severity?
Level 7
```

This is substantially more useful for SIEM triage than a raw packet
capture alone.

------------------------------------------------------------------------

# 16. What Evidence Is Missing?

No additional evidence is required to close the demonstrated Case 07
scenario.

However, the current evidence set does **not** attempt to prove every
possible reconnaissance technique.

For example, this case does not establish:

-   complete host discovery across an entire subnet,
-   complete service enumeration of every port,
-   successful SMB authentication,
-   exploitation of SMB,
-   credential access,
-   lateral movement,
-   or post-exploitation activity.

Those are outside the demonstrated scope of this case.

### Important distinction

``` text
Reconnaissance observed
        ≠
Successful compromise
```

The evidence demonstrates reconnaissance/connection activity and
firewall enforcement. It does **not** demonstrate successful
exploitation.

------------------------------------------------------------------------

# 17. Evidence Strength

## Primary Evidence

### 1. Kali Nmap result

Proves the attacker-side observation:

``` text
TCP/445 = filtered
```

### 2. Windows Firewall DROP evidence

Proves the victim-side enforcement:

``` text
192.168.56.106 → 192.168.56.105:445
DROP
```

### 3. Wazuh Dashboard

Proves SIEM visibility:

``` text
Agent 002
Rule 100100
Level 7
2 hits
```

### 4. Wazuh Document Details

Proves normalized fields:

``` text
srcip
dstip
srcport
dstport
protocol
action
decoder
rule
location
```

------------------------------------------------------------------------

# 18. Evidence Chain

The final evidence chain is:

``` text
                ATTACKER
             Kali Linux
          192.168.56.106
                 |
                 | TCP reconnaissance
                 v
              NETWORK
             Wireshark
                 |
                 v
               VICTIM
        Windows 11 / Agent 002
          192.168.56.105
                 |
                 | Windows Firewall
                 | DROP TCP/445
                 v
          pfirewall.log
                 |
                 v
             WAZUH
       windows-firewall decoder
                 |
                 v
            Rule 4101
                 |
                 v
           Rule 100100
             Level 7
                 |
                 v
       Wazuh alerts.json
                 |
                 v
       Wazuh Dashboard
```

------------------------------------------------------------------------

# 19. Final Findings

### Finding 1 --- TCP/445 is filtered

Kali reconnaissance identified:

``` text
445/tcp filtered
```

### Finding 2 --- Windows Firewall is enforcing the filtering

Windows recorded TCP DROP events from:

``` text
192.168.56.106
```

toward:

``` text
192.168.56.105:445
```

### Finding 3 --- Network telemetry corroborates reconnaissance

Wireshark captured the relevant network activity and provides
network-level context.

### Finding 4 --- Wazuh can normalize the firewall telemetry

The event was decoded into structured:

``` text
action
protocol
srcip
srcport
dstip
dstport
```

### Finding 5 --- Wazuh generated a case-specific alert

Rule:

``` text
100100
```

Severity:

``` text
7
```

Description:

``` text
Windows Firewall DROP event - logged for Case 7.
```

### Finding 6 --- SIEM visibility was confirmed

The event was confirmed in:

-   `alerts.json`
-   Wazuh Dashboard
-   Wazuh Document Details

------------------------------------------------------------------------

# 20. Final Assessment

  -----------------------------------------------------------------------
  Question                            Answer
  ----------------------------------- -----------------------------------
  What can an attacker discover?      TCP/445 is visible as a filtered
                                      target on the Windows host.

  What does the victim observe?       Windows Firewall records the
                                      TCP/445 connection attempt as
                                      `DROP`.

  What does the network observe?      Wireshark provides
                                      packet/network-level corroboration
                                      of the reconnaissance activity.

  What does Wazuh observe?            Wazuh receives, decodes, classifies
                                      and alerts on the firewall DROP
                                      event.

  What evidence is missing?           No evidence is required for this
                                      case's defined reconnaissance
                                      scope; exploitation/compromise was
                                      not investigated.
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# 21. Case Conclusion

> **CASE 07 --- NETWORK RECONNAISSANCE: VALIDATED**

The controlled reconnaissance activity from Kali (`192.168.56.106`)
toward Windows 11 (`192.168.56.105`) was observed from multiple
defensive layers.

The attacker-side result showed TCP/445 as filtered.

The Windows victim recorded corresponding firewall DROP events.

Wireshark provided network-level corroboration.

Wazuh successfully processed the Windows firewall telemetry, decoded the
relevant fields, matched firewall detection logic, generated the Case 07
level-7 rule `100100` alert, persisted the alert, and displayed it in
the Dashboard.

The investigation therefore demonstrates the intended **Attacker →
Victim → Defender** workflow.

``` text
ATTACKER
Kali
192.168.56.106
       |
       v
RECONNAISSANCE
TCP/445
       |
       v
VICTIM
Windows 11
192.168.56.105
       |
       v
FIREWALL
DROP
       |
       v
WAZUH
Rule 100100
Level 7
       |
       v
SOC VISIBILITY
Dashboard + alerts.json
```

**Case 07 is closed and ready for the next case.**

------------------------------------------------------------------------

## Related Technical Report

The detailed technical troubleshooting report is maintained separately:

``` text
SOC-Lab/
└── home-lab-soc-1/
    └── docs/
        └── Case 7/
            └── Case_7_Windows_Firewall_DROP_Detection_Report.docx
```

That report documents the decoder troubleshooting and Wazuh rule
validation in greater technical detail. This investigation file remains
focused on **Case 07 --- Network Reconnaissance**.
