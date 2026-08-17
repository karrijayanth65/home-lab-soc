# 🛡️ Home Lab SOC

A hands-on cybersecurity laboratory built to develop practical **SOC, Blue Team, threat detection, investigation, threat hunting, incident response, detection engineering, and security automation skills**.

This project is intentionally designed as a **learning laboratory rather than a tool-specific laboratory**.

Wazuh is currently the central SIEM/XDR platform, but the laboratory will use whatever technologies, telemetry sources, frameworks, and analysis tools are necessary to understand the underlying security concepts properly.

The central philosophy is:

> **Understand the adversary → understand the evidence → detect the behavior → investigate it → respond to it → improve the defense.**

---

# 🎯 Project Mission

The goal of this project is to develop the ability to think and operate like a security analyst.

The lab will progressively teach:

- How systems generate security telemetry
- How attackers create observable behavior
- How defenders collect telemetry
- How detections are created
- How alerts are triaged
- How investigations are performed
- How multiple events are correlated
- How attack timelines are reconstructed
- How indicators are identified
- How adversary behavior maps to MITRE ATT&CK
- How detection gaps are discovered
- How detections are engineered and tuned
- How incidents are contained and remediated
- How threat hunting is performed
- How security operations can be automated
- How investigations are documented professionally

The project is therefore **not a Wazuh-learning project**.

Wazuh is one of the major platforms used to implement and demonstrate the concepts.

The concepts come first.

---

# 🧠 Core Learning Philosophy

A capable defender should understand the behavior they are defending against.

Therefore, the laboratory deliberately combines:

```text
Adversary Understanding
        ↓
Security Telemetry
        ↓
Detection
        ↓
Investigation
        ↓
Threat Hunting
        ↓
Incident Response
        ↓
Detection Engineering
        ↓
Automation
        ↓
Continuous Improvement
````

The purpose of using an attacker platform is not to learn offensive tools for their own sake.

The purpose is to understand:

* What an attacker is trying to achieve
* What actions are required
* What artifacts those actions create
* Where those artifacts appear
* What telemetry defenders can collect
* What defenders cannot see
* How detection can fail
* How analysts can investigate the activity
* How defensive controls can be improved

---

# 🏗️ Lab Architecture

The architecture separates the attacker, victim, and SOC roles.

```text
                         HOME SOC LAB
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
       ATTACKER             VICTIMS          SOC PLATFORM
          │                   │                   │
    ┌───────────┐       ┌─────────────┐     ┌─────────────┐
    │   Kali    │       │ Windows 10  │────▶│    Wazuh    │
    │  Linux    │       │   Victim    │     │    Stack    │
    └─────┬─────┘       └─────────────┘     └──────┬──────┘
          │                                         │
          │                  ┌─────────────┐        │
          └─────────────────▶│ Linux Lab   │────────┤
                             │   Victim     │        │
                             └─────────────┘        │
                                                    ▼
                                             Investigation
                                                    │
                                                    ▼
                                           Detection / Hunt
                                                    │
                                                    ▼
                                             Response
                                                    │
                                                    ▼
                                           Documentation
```

## Current Roles

| Component         | Role                    | Purpose                            |
| ----------------- | ----------------------- | ---------------------------------- |
| Kali Linux        | Controlled attacker     | Adversary simulation               |
| Windows 10        | Victim endpoint         | Windows security telemetry         |
| Ubuntu Linux      | SOC infrastructure      | Wazuh/Docker platform              |
| Linux endpoint(s) | Future victim           | Linux security telemetry           |
| Wazuh             | SIEM/XDR platform       | Collection, analysis and detection |
| Git/GitHub        | Engineering + portfolio | Documentation and evidence         |

The architecture will expand when a new security concept requires additional visibility.

---

# 🧩 Tool-Agnostic Learning Principle

Tools are selected because they teach or provide visibility into a security concept.

They are not goals by themselves.

For example:

```text
Security Concept
      ↓
What evidence is required?
      ↓
Which telemetry source provides it?
      ↓
Which tool collects it?
      ↓
Which detection method analyzes it?
      ↓
How does the analyst investigate it?
```

Possible technologies may include:

### Endpoint telemetry

* Windows Security Event Logs
* Sysmon
* Windows Defender telemetry
* Linux audit/logging
* Endpoint inventory
* File Integrity Monitoring

Sysmon is particularly useful for high-fidelity endpoint telemetry such as process creation, network connections and file-related activity. It generates telemetry but does not itself perform detection, which makes it useful for learning the distinction between **telemetry, detection and response**.

### Network visibility

* Wireshark
* Zeek
* Suricata
* PCAP analysis
* DNS visibility
* HTTP/TLS visibility
* Network flow analysis

Zeek provides detailed network activity logs useful for investigation, while Suricata provides IDS/IPS and network-security-monitoring capabilities with structured outputs such as EVE JSON.

### Detection engineering

* Wazuh rules
* Sigma
* Custom detection logic
* Correlation
* Detection tuning
* MITRE ATT&CK Detection Strategies

Sigma will be introduced when the project reaches the point where portable, vendor-neutral detection logic becomes useful.

### Investigation / DFIR

Additional tools may be introduced if the investigation requires deeper endpoint visibility, forensic collection, or timeline reconstruction.

Potential technologies include:

* Velociraptor
* Windows forensic utilities
* Linux forensic utilities
* Memory-analysis tooling
* PCAP analysis tools

These are **candidate capabilities**, not mandatory dependencies.

---

# 🧭 Tool Procurement Principle

I will not assume that the current toolset is sufficient for every future investigation.

If a future case would be significantly improved by adding:

* A new VM
* A new monitoring sensor
* Additional storage
* More RAM/CPU
* Sysmon
* Zeek
* Suricata
* Wireshark
* Velociraptor
* Sigma tooling
* A vulnerable laboratory application
* A Windows Server / Active Directory environment
* Another Linux distribution
* Additional network segmentation
* A dedicated analysis machine

I will explicitly tell you:

```text
WHY we need it
WHAT it teaches
WHERE it fits
WHAT resources it requires
WHETHER it is optional or recommended
```

We will then decide whether to add it.

**No unnecessary tool collection.**

---

# 🛡️ Start / Stop Operating Rules

These rules are mandatory for the laboratory.

## ▶️ START RULE

Before starting a case:

1. Define the investigation objective.
2. Identify attacker, victim and SOC components.
3. Start only the machines required for the case.
4. Start required monitoring infrastructure.
5. Verify the Wazuh stack if it is being used.
6. Verify the relevant endpoint agents.
7. Verify network connectivity.
8. Verify the attacker is connected only to the authorized lab network.
9. Establish the baseline state.
10. Create or confirm a VM snapshot when appropriate.
11. Confirm what evidence must be captured.
12. Only then generate the controlled security activity.

Typical startup:

```text
Define Objective
      ↓
Start Required VMs
      ↓
Verify Network Isolation
      ↓
Verify Monitoring
      ↓
Verify Victim Baseline
      ↓
Verify Evidence Plan
      ↓
Run Controlled Activity
```

---

## ⏹️ STOP RULE

When the case is complete:

1. Stop the test activity.
2. Stop temporary processes.
3. Remove temporary persistence.
4. Remove temporary services/tasks/accounts/files when appropriate.
5. Restore the intended victim state.
6. Verify cleanup.
7. Preserve useful evidence.
8. Capture final screenshots.
9. Complete the investigation documentation.
10. Review the Git changes.
11. Commit the completed case.
12. Push to GitHub.
13. Verify the remote repository.
14. Stop unnecessary VMs/services.
15. Shut down the laboratory when the session is finished.

Typical shutdown:

```text
Stop Attack
     ↓
Cleanup
     ↓
Verify Cleanup
     ↓
Capture Evidence
     ↓
Document
     ↓
Git Commit
     ↓
Git Push
     ↓
Verify Remote
     ↓
Stop Unnecessary Infrastructure
```

> **No temporary attack artifact, persistence mechanism, account, service, scheduled task, process, test configuration or exposed service should remain active after a case unless intentionally required for the next case.**

---

# 🧪 Course Structure

The laboratory is organized as a progressive cybersecurity course.

The cases are not independent demonstrations.

Each case should build on knowledge from previous cases.

```text
FOUNDATIONS
    ↓
TELEMETRY
    ↓
ATTACKER BEHAVIOR
    ↓
DETECTION
    ↓
INVESTIGATION
    ↓
CORRELATION
    ↓
THREAT HUNTING
    ↓
DETECTION ENGINEERING
    ↓
INCIDENT RESPONSE
    ↓
AUTOMATION
    ↓
CAPSTONE
```

---

# 📚 Investigation Roadmap

The initial course target is **15 major cases**.

The roadmap is intentionally flexible.

If a case reveals an important missing concept, the course may add a supporting lab before continuing.

---

# 🟢 PHASE 1 — Security Foundations

## Case 01 — Windows File Integrity Monitoring

**Concepts**

* File integrity
* File changes
* Endpoint monitoring
* Baselines
* Evidence

**Status:** ✅ Completed

---

## Case 02 — Windows Authentication Failures

**Concepts**

* Authentication
* Security events
* Failed logons
* Account investigation
* Source identification

**Status:** ✅ Completed

---

## Case 03 — PowerShell Telemetry

**Primary telemetry**

* Event ID 4104

**Concepts**

* Script execution
* PowerShell logging
* Command visibility
* Script investigation
* Detection logic

**Status:** ✅ Completed

---

## Case 04 — Process Creation

**Primary telemetry**

* Event ID 4688

**Concepts**

* Process creation
* Parent/child relationships
* Process IDs
* Command lines
* Execution chains
* Process correlation

**Status:** ✅ Completed

---

## Case 05 — Windows Service Creation

**Primary telemetry**

* Event ID 7045

**Concepts**

* Service installation
* Persistence
* Execution
* Service investigation
* Detection

**Status:** ✅ Completed

---

## Case 06 — Scheduled Task Creation

**Primary telemetry**

* Event ID 4698
* Event ID 4688
* Event ID 4699

**Concepts**

* Scheduled task persistence
* Execution
* Process correlation
* MITRE ATT&CK
* Detection gaps
* Cleanup verification

**Status:** ✅ Completed

---

# 🔴 PHASE 2 — Attacker → Victim → Defender

This phase introduces Kali as a controlled attacker platform.

The purpose is to understand attacker behavior from a defender's perspective.

---

## Case 07 — Network Reconnaissance

**Concepts**

* Discovery
* Attack surface
* Ports
* Services
* Network visibility
* Endpoint visibility
* Network telemetry

**Questions**

* What can an attacker discover?
* What does the victim observe?
* What does the network observe?
* What does Wazuh observe?
* What evidence is missing?

**Potential tools**

* Kali
* Wireshark
* Zeek
* Windows telemetry
* Wazuh

**Status:** ✅ Completed

---

## Case 08 — [Authentication Attack Simulation](investigations/008-authentication_attack_simulation-60204.md)

**Concepts**

* Authentication
* Failed logons
* Successful logons
* Account targeting
* Source IP
* Repeated attempts
* Detection thresholds

**Potential telemetry**

* Windows Security Events
* Wazuh
* Network telemetry

**Status:** ✅ Completed

---

## Case 09 — [SMB / Network Resource Access](investigations/009-windows-smb-detailed-file-share-access-5145.md)

**Concepts**

* SMB
* Network shares
* Authentication
* Resource access
* User context
* Network-to-endpoint correlation

**Potential telemetry**

* Windows Security Logs
* SMB-related telemetry
* Network monitoring
* Wazuh

**Status:** ✅ Completed

---

## Case 10 — Remote Execution

**Concepts**

* Remote access
* Authentication
* Remote execution
* PowerShell
* Process creation
* Parent/child correlation
* Multi-source investigation

**Potential telemetry**

* Windows Security Events
* PowerShell
* Sysmon
* Network telemetry
* Wazuh

**Status:** 🔜 Planned

---

## Case 11 — Defense Evasion / Living-off-the-Land Concepts

**Concepts**

* Legitimate system tools
* Suspicious command lines
* Process relationships
* Execution context
* Evasion concepts
* Behavioral detection

**Key lesson**

A suspicious action does not necessarily require a suspicious executable.

**Status:** 🔜 Planned

---

# 🟣 PHASE 3 — Threat Hunting & Detection Engineering

---

## Case 12 — Detection Gap Investigation

**Objective**

Find behavior that occurred but was not adequately detected.

Investigation:

```text
Behavior
   ↓
Telemetry Generated?
   ↓
Telemetry Collected?
   ↓
Decoded?
   ↓
Detection Rule?
   ↓
Alert Generated?
   ↓
Correct Severity?
   ↓
Detection Gap?
```

**Concepts**

* Visibility
* Coverage
* Decoders
* Detection rules
* Detection limitations
* False negatives

**Status:** 🔜 Planned

---

## Case 13 — Custom Detection Engineering

**Objective**

Build a useful detection from an observed security behavior.

```text
Security Behavior
       ↓
Required Evidence
       ↓
Detection Logic
       ↓
Rule
       ↓
Test
       ↓
Alert
       ↓
Tune
       ↓
Validate
       ↓
Document
```

**Concepts**

* Detection design
* Rule logic
* False positives
* Severity
* Correlation
* MITRE mapping
* Detection testing

**Potential technologies**

* Wazuh
* Sigma
* MITRE ATT&CK

**Status:** 🔜 Planned

---

# 🟠 PHASE 4 — Advanced Investigation

---

## Case 14 — Multi-Stage Attack Chain

**Objective**

Investigate multiple related activities as one incident.

Example:

```text
Recon
  ↓
Authentication
  ↓
Access
  ↓
Execution
  ↓
Persistence
  ↓
Detection
```

**Concepts**

* Timeline reconstruction
* Correlation
* Threat hunting
* Attack-chain analysis
* Scope
* MITRE ATT&CK
* Detection coverage

**Status:** 🔜 Planned

---

## Case 15 — Full SOC Incident Response Capstone

The final planned case will simulate a complete incident.

The analyst will be expected to:

```text
Detect
  ↓
Validate
  ↓
Triage
  ↓
Investigate
  ↓
Correlate
  ↓
Scope
  ↓
Identify Impact
  ↓
Contain
  ↓
Eradicate
  ↓
Recover
  ↓
Hunt for Residual Activity
  ↓
Improve Detection
  ↓
Document
```

The final case should demonstrate the complete skill set developed throughout the course.

**Status:** 🔜 Planned

---

# 🧠 Core SOC Methodology

Every investigation should answer:

## What happened?

Describe the observed behavior.

## Who performed it?

Identify:

* Account
* Process
* Source host
* Source IP
* Parent process
* User context

## Where did it happen?

Identify:

* Endpoint
* Service
* File
* Network resource
* Process

## When did it happen?

Construct a timeline.

## How did it happen?

Understand the execution chain.

## What evidence proves it?

Identify the relevant telemetry.

## Was it detected?

Identify:

* Detection
* Rule
* Severity
* Alert

## What did the defender miss?

Identify gaps.

## What is the scope?

Determine whether the activity is isolated or part of a broader chain.

## What should happen next?

Determine:

* Containment
* Eradication
* Recovery
* Monitoring
* Detection improvement

---

# 🗺️ MITRE ATT&CK Methodology

MITRE ATT&CK is used as an **analytical framework**, not merely a list of technique numbers.

For each applicable investigation we should document:

```text
Tactic
Technique
Sub-technique
Technique ID
Observed Behavior
Supporting Evidence
Reason for Mapping
Detection Opportunity
```

Where appropriate, the investigation should also consider ATT&CK **Data Components** and **Detection Strategies** to understand what telemetry and analytical approaches support detection. ([MITRE ATT&CK][5])

---

# 🕵️ Threat Hunting

Threat hunting will progressively move beyond alert-driven investigation.

Example hunting questions:

* What unusual processes were created?
* Which accounts experienced repeated failures?
* Which hosts contacted unusual services?
* Which new services appeared?
* Which scheduled tasks were created?
* Which PowerShell activity occurred?
* Which network connections preceded execution?
* Which events occurred before and after a suspicious alert?
* Are multiple apparently unrelated events actually one attack chain?

The progression is:

```text
Alert Triage
    ↓
Event Investigation
    ↓
Query-Based Investigation
    ↓
Hypothesis
    ↓
Threat Hunt
    ↓
Attack-Chain Reconstruction
```

---

# 🔬 Telemetry & Visibility

A major objective of this project is learning that **no single telemetry source tells the complete story**.

We will progressively compare:

```text
Endpoint Telemetry
       +
Network Telemetry
       +
Authentication Telemetry
       +
Process Telemetry
       +
File Telemetry
       +
Application Telemetry
       +
Security Alerts
       =
Better Investigation
```

We will deliberately examine situations where:

* The endpoint sees something but the network does not.
* The network sees something but the endpoint does not.
* Telemetry exists but no detection exists.
* A detection exists but lacks context.
* A detection produces too many false positives.
* Multiple low-severity events become important when correlated.

---

# 🛠️ Detection Engineering

Detection engineering will focus on **behavior**, not merely event IDs.

A mature detection workflow:

```text
Threat Behavior
      ↓
Required Evidence
      ↓
Telemetry Source
      ↓
Detection Logic
      ↓
Rule / Analytic
      ↓
Test
      ↓
False-Positive Review
      ↓
Tune
      ↓
Validate
      ↓
Document
```

Detection work may use:

* Wazuh rules
* Sigma
* Endpoint telemetry
* Network telemetry
* MITRE ATT&CK
* Correlation
* Custom scripts

Wazuh custom rules are useful for environment-specific detection logic, while Sigma provides a vendor-neutral YAML format for detection rules that can be translated to different SIEM/query backends. ([Wazuh Documentation][6])

---

# 🚨 Incident Response

The project will progressively teach:

## Preparation

* Logging
* Monitoring
* Baselines
* Snapshots
* Evidence procedures

## Identification

* Alert validation
* Triage
* Correlation
* Scope assessment

## Containment

* Isolating affected systems
* Stopping malicious/test activity
* Removing temporary persistence
* Preserving evidence

## Eradication

* Removing persistence
* Removing malicious/test artifacts
* Restoring configuration

## Recovery

* Restoring normal operation
* Verifying monitoring
* Validating endpoint state

## Lessons Learned

* What happened?
* What worked?
* What failed?
* What was missed?
* What should be improved?

---

# 🤖 Security Automation

Automation will be introduced only after the underlying process is understood.

Potential areas:

* Wazuh API
* Python
* PowerShell
* Bash
* Alert enrichment
* Evidence collection
* Detection testing
* Telegram notifications
* Automated reporting
* Security workflows

The Wazuh API provides programmatic access to management, FIM, rules, MITRE-related information, Syscollector and other capabilities, making it useful for later automation work. ([Wazuh Documentation][4])

The rule is:

> **Understand manually first → automate second.**

---

# 📸 Evidence Standards

Evidence is part of the investigation.

Screenshots should prove an observation, not merely show that a command was typed.

Useful evidence includes:

* Security events
* Process details
* Network activity
* Wazuh alerts
* Wazuh document details
* Rule information
* MITRE mappings
* Configuration
* Detection results
* Cleanup results

## Naming Convention

Use descriptive names.

Example:

```text
PS_01_4698_audit_enabled.png
PS_02_4698_task_created.png
PS_03_4688_notepad_process_details.png
Wazuh_01_4698_ingested.png
Wazuh_02_4698_task_details.png
Wazuh_03_rule_60228_T1053.png
PS_05_4698_cleanup.png
```

The exact numbering may change between cases.

The principle is:

> **A filename should tell us what the evidence proves.**

---

# 📝 Investigation Documentation Standard

Every major investigation should contain:

```text
Title
Objective
Security Concept
Environment
Prerequisites
Baseline
Test / Attack Simulation
Observed Behavior
Telemetry
Timeline
Evidence
Detection
Detection Logic
MITRE ATT&CK
Indicators
Investigation Findings
Scope
Impact
Response
Cleanup
Detection Gaps
Recommendations
Lessons Learned
```

---

# 🔄 Case Completion Standard

A case is complete only when:

```text
[ ] Objective defined
[ ] Security concept understood
[ ] Required resources identified
[ ] Lab prepared
[ ] Start Rule followed
[ ] Baseline established
[ ] Controlled activity performed
[ ] Telemetry confirmed
[ ] Detection investigated
[ ] Evidence captured
[ ] Timeline reconstructed
[ ] Indicators identified
[ ] MITRE mapping completed
[ ] Scope assessed
[ ] Response performed
[ ] Cleanup completed
[ ] Cleanup verified
[ ] Detection gaps analyzed
[ ] Lessons learned documented
[ ] Investigation report completed
[ ] Screenshots organized
[ ] Git status reviewed
[ ] Git diff reviewed
[ ] Commit created
[ ] Push completed
[ ] Remote repository verified
[ ] Stop Rule followed
```

---

# 🌳 Git / Documentation Workflow

Git is part of the engineering discipline of this project.

For every completed investigation:

```text
Investigation
     ↓
Evidence Review
     ↓
Documentation
     ↓
git status
     ↓
git diff
     ↓
git diff --cached
     ↓
Commit
     ↓
Fetch / Rebase if required
     ↓
Push
     ↓
Verify Remote
```

Git work should remain clean and understandable.

Commit messages should describe the completed investigation.

Example:

```text
Add Windows scheduled task 4698 investigation
```

For future Git work, the objective is to develop independence:

> **You perform the Git workflow yourself.**
>
> I provide a task, you perform it, and we troubleshoot only if you encounter an issue.

---

# 📂 Repository Structure

```text
home-lab-soc/
│
├── architecture/
│   └── lab-topology.md
│
├── attacks/
│   ├── authentication/
│   ├── network/
│   ├── endpoint/
│   ├── execution/
│   ├── persistence/
│   └── defense-evasion/
│
├── detections/
│   ├── custom-rules/
│   ├── sigma/
│   ├── detection-notes.md
│   └── tuning/
│
├── docs/
│   ├── setup/
│   ├── learning-notes/
│   └── troubleshooting/
│
├── investigations/
│   ├── 001-windows-fim.md
│   ├── 002-windows-authentication-failure.md
│   ├── 003-windows-powershell-4104.md
│   ├── 004-windows-process-creation-4688.md
│   ├── 005-windows-service-creation-7045.md
│   ├── 006-windows-scheduled-task-4698.md
│   └── ...
│
├── response/
│   ├── incident-response/
│   ├── containment/
│   ├── eradication/
│   └── recovery/
│
├── scripts/
│   ├── python/
│   ├── powershell/
│   └── bash/
│
├── screenshots/
│   ├── Case 1/
│   ├── Case 2/
│   ├── Case 3/
│   ├── Case 4/
│   ├── Case 5/
│   ├── Case 6/
│   └── ...
│
├── wazuh/
│   ├── deployment/
│   ├── agents/
│   ├── rules/
│   └── configuration/
│
├── .gitignore
└── README.md
```

Directories may be introduced gradually as the corresponding learning area becomes active.

---

# 📈 Project Progress

## Environment

* [x] VirtualBox environment
* [x] Ubuntu VM
* [x] Ubuntu resources configured
* [x] Docker installed
* [x] Docker Compose installed
* [x] Windows 10 laboratory VM
* [x] Kali Linux laboratory VM
* [ ] Document final lab topology
* [ ] Finalize network segmentation
* [ ] Establish snapshot strategy
* [ ] Evaluate additional analysis/monitoring resources

## SOC Platform

* [x] Wazuh Docker environment
* [x] Wazuh Manager
* [x] Wazuh Indexer
* [x] Wazuh Dashboard
* [x] Windows agent enrollment
* [x] Windows endpoint visibility
* [ ] Linux endpoint monitoring
* [ ] Sysmon telemetry
* [ ] Network telemetry
* [ ] Advanced collection
* [ ] Detection tuning

## Investigation

* [x] Case 01 — Windows FIM
* [x] Case 02 — Windows Authentication Failure
* [x] Case 03 — PowerShell 4104
* [x] Case 04 — Process Creation 4688
* [x] Case 05 — Service Creation 7045
* [x] Case 06 — Scheduled Task 4698
* [ ] Case 07 — Network Reconnaissance
* [ ] Case 08 — Authentication Attack
* [ ] Case 09 — SMB / Resource Access
* [ ] Case 10 — Remote Execution
* [ ] Case 11 — Defense Evasion
* [ ] Case 12 — Detection Gap
* [ ] Case 13 — Custom Detection
* [ ] Case 14 — Attack Chain
* [ ] Case 15 — SOC Capstone

## Detection Engineering

* [ ] Detection gap analysis
* [ ] Wazuh custom rules
* [ ] Sigma fundamentals
* [ ] Detection testing
* [ ] Detection tuning
* [ ] Correlation
* [ ] MITRE ATT&CK Detection Strategies
* [ ] Detection coverage analysis

## Threat Hunting

* [ ] Baseline-driven hunting
* [ ] Hypothesis-driven hunting
* [ ] Endpoint hunting
* [ ] Network hunting
* [ ] Cross-source correlation
* [ ] Attack-chain hunting

## Incident Response

* [ ] Evidence preservation
* [ ] Alert triage
* [ ] Containment
* [ ] Eradication
* [ ] Recovery
* [ ] Lessons learned
* [ ] Full incident-response exercise

## Automation

* [ ] Wazuh API
* [ ] Python automation
* [ ] PowerShell automation
* [ ] Telegram alerting
* [ ] Automated evidence collection
* [ ] Detection validation automation

---

# 🧭 Learning Progression

The laboratory is designed to increase difficulty gradually.

```text
LEVEL 1
Understand Security Events
        ↓
LEVEL 2
Understand Endpoint Telemetry
        ↓
LEVEL 3
Understand Detection
        ↓
LEVEL 4
Understand Attacker Behavior
        ↓
LEVEL 5
Generate Controlled Attacker Activity
        ↓
LEVEL 6
Investigate Events
        ↓
LEVEL 7
Correlate Multiple Sources
        ↓
LEVEL 8
Threat Hunt
        ↓
LEVEL 9
Engineer Detections
        ↓
LEVEL 10
Investigate Attack Chains
        ↓
LEVEL 11
Perform Incident Response
        ↓
LEVEL 12
Automate Repetitive SOC Work
        ↓
SOC ANALYST PORTFOLIO
```

---

# 🧪 Learning Rules

The laboratory follows several principles.

## 1. Understand before executing

Before using a command or tool, understand what it is intended to demonstrate.

## 2. Attack only the lab

All offensive activity remains inside the authorized laboratory.

## 3. Evidence before assumptions

Conclusions must be supported by telemetry.

## 4. Correlate before concluding

One event rarely tells the entire story.

## 5. Detection is not visibility

A system may generate telemetry without generating an alert.

## 6. Tools are means, not goals

Learning the security concept is more important than memorizing a tool.

## 7. Automate only after understanding

Manual understanding comes before automation.

## 8. Document everything important

If an investigation is not documented, it is difficult to reproduce or defend.

## 9. Clean the lab

Temporary attack artifacts must not become permanent accidental persistence.

## 10. Build portfolio-quality evidence

Every major case should demonstrate practical reasoning, not just command execution.

---

# 🏆 Portfolio Outcome

The completed project should demonstrate practical capability in:

## Security Operations

* Alert triage
* Log analysis
* SIEM operations
* Investigation
* Threat hunting
* Timeline reconstruction

## Endpoint Security

* Windows security telemetry
* Linux security telemetry
* PowerShell
* Processes
* Services
* Scheduled Tasks
* Authentication
* File Integrity Monitoring
* Endpoint investigation

## Network Security

* Reconnaissance
* Network discovery
* Network traffic analysis
* DNS
* HTTP/TLS visibility
* Network detection
* PCAP investigation

## Adversary Understanding

* Discovery
* Authentication attacks
* Network access
* Execution
* Persistence
* Defense evasion
* Attack-chain behavior

## Detection Engineering

* Detection logic
* Wazuh rules
* Sigma
* Detection tuning
* Detection gaps
* Correlation
* MITRE ATT&CK

## Incident Response

* Evidence collection
* Triage
* Containment
* Eradication
* Recovery
* Lessons learned

## Security Engineering

* Linux
* Docker
* Bash
* PowerShell
* Python
* APIs
* Git
* Automation

---

# 🔭 Future Capability Expansion

The 15 cases are the initial structured course.

The project may expand beyond Case 15 when additional capabilities provide meaningful learning value.

Possible future areas include:

* Active Directory security
* Windows Server
* Kerberos
* LDAP
* Group Policy
* Identity attacks
* Web application security
* Vulnerable applications
* Container security
* Cloud security concepts
* Malware analysis
* Memory forensics
* Digital forensics
* Network detection engineering
* Purple-team exercises
* Detection-as-code
* Security automation
* SOAR concepts

These are **future possibilities, not commitments**.

The course will only add them when the current skill level and lab architecture justify them.

---

# 🔄 Continuous Learning Cycle

The entire laboratory follows:

```text
LEARN
  ↓
BUILD
  ↓
SIMULATE
  ↓
OBSERVE
  ↓
DETECT
  ↓
INVESTIGATE
  ↓
HUNT
  ↓
RESPOND
  ↓
IMPROVE
  ↓
AUTOMATE
  ↓
DOCUMENT
  ↓
REPEAT
```

The objective is not to collect tools.

The objective is to develop the ability to answer:

> **What happened?**
>
> **How do I know?**
>
> **What evidence supports the conclusion?**
>
> **What was the attacker trying to achieve?**
>
> **What telemetry should have captured it?**
>
> **What did the detection system see?**
>
> **What did it miss?**
>
> **How should the SOC respond?**
>
> **How can we improve the defense?**

---

# 🚧 Project Status

**Status:** 🚧 Active Development

**Current Phase:** Phase 1 completed → Phase 2 preparation

**Completed Investigations:** 6 / 15

**Current Milestone:** Transition from Windows security foundations to attacker-informed defensive investigation.

**Next Major Case:** Case 07 — Network Reconnaissance

---

# 👨‍💻 Project Focus

**SOC Operations | Blue Team | SIEM/XDR | Endpoint Security | Network Security | Threat Detection | Threat Hunting | Detection Engineering | Incident Response | MITRE ATT&CK | Security Automation**

---

# ⭐ Final Objective

Build a realistic, isolated, continuously evolving security laboratory that demonstrates the ability to:

```text
Understand
    ↓
Simulate
    ↓
Observe
    ↓
Detect
    ↓
Investigate
    ↓
Correlate
    ↓
Hunt
    ↓
Respond
    ↓
Engineer Better Detection
    ↓
Automate
    ↓
Document
```

> **Learn the behavior.**
>
> **Understand the evidence.**
>
> **Detect the threat.**
>
> **Investigate the incident.**
>
> **Defend the environment.**
>
> **Improve the SOC.**
