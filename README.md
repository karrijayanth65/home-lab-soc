# 🛡️ Home Lab SOC

A hands-on Security Operations Center (SOC) laboratory built to develop practical skills in security monitoring, SIEM/XDR, threat detection, investigation, incident response, and security automation.

---

## 🎯 Project Objectives

- Build a functional home SOC environment
- Deploy Wazuh as the central SIEM/XDR platform
- Monitor Windows and Linux endpoints
- Generate controlled security events in an isolated lab
- Investigate alerts and identify indicators of compromise
- Understand detection rules and log sources
- Map security activity to MITRE ATT&CK
- Practice incident response and defensive techniques
- Develop detection engineering and security automation skills
- Document the entire journey professionally

---

## 🏗️ Planned Lab Architecture

```text
                         HOME SOC LAB
                              │
                      ┌───────┴───────┐
                      │     Wazuh     │
                      │   SIEM / XDR  │
                      └───────┬───────┘
                              │
             ┌────────────────┼────────────────┐
             │                │                │
          Windows           Ubuntu           Kali
          Endpoint          Endpoint        Security
             │                │                │
             └────────────────┼────────────────┘
                              │
                         Monitoring
                              │
                       Detection & Alert
                              │
                         Investigation
                              │
                           Response
````

> Architecture will be updated as the lab expands.

---

## 🧰 Technologies

### Core Infrastructure

* Wazuh
* Docker
* Docker Compose
* VirtualBox
* Ubuntu Linux
* Windows
* Kali Linux

### Development & Documentation

* Git
* GitHub
* Visual Studio Code
* Python
* Bash
* PowerShell
* Markdown

### Security & Monitoring

* Wazuh SIEM/XDR
* Sysmon
* MITRE ATT&CK
* Wireshark
* Network monitoring
* Endpoint monitoring
* File Integrity Monitoring

### Planned Integrations

* Telegram alerting
* Security automation
* Custom detection rules
* API integrations

---

## 🔍 Security Lab Areas

### 1. Monitoring

The lab will focus on monitoring:

* Endpoint activity
* Authentication events
* Process activity
* File changes
* File Integrity Monitoring
* Windows Security Events
* Linux authentication events
* Network activity
* Suspicious behavior

---

### 2. Attack Simulation

Controlled security testing will be performed only against intentionally created laboratory systems.

Planned areas include:

* Authentication attack simulations
* Network reconnaissance
* Suspicious process activity
* Web/application security testing
* Persistence concepts
* Privilege escalation concepts
* Malware-analysis concepts using safe test samples

> All testing will remain inside the isolated laboratory environment.

---

### 3. Detection

For each security event, I will study:

* What happened?
* Which log was generated?
* Which endpoint generated the event?
* What data did Wazuh collect?
* Which detection rule triggered?
* Why did the rule trigger?
* What indicators are present?
* What is the severity?
* What MITRE ATT&CK technique applies?

---

### 4. Investigation

Each investigation will follow a SOC analyst workflow:

```text
Alert
  ↓
Validate
  ↓
Collect Evidence
  ↓
Analyze
  ↓
Identify Indicators
  ↓
Determine Scope
  ↓
Map to MITRE ATT&CK
  ↓
Determine Impact
  ↓
Respond
  ↓
Document
```

---

### 5. Incident Response

The lab will be used to practice:

* Alert triage
* Investigation
* Containment concepts
* Eradication concepts
* Recovery concepts
* Evidence collection
* Incident documentation
* Lessons learned

---

## 🧪 Planned Attack & Detection Labs

Future labs may include:

| Lab                           | Objective                                      | Status    |
| ----------------------------- | ---------------------------------------------- | --------- |
| SSH Authentication Monitoring | Understand Linux authentication logs           | ⏳ Planned |
| Brute-Force Detection         | Study repeated authentication failures         | ⏳ Planned |
| Windows Login Monitoring      | Understand Windows authentication events       | ⏳ Planned |
| Suspicious Process Detection  | Investigate unusual process activity           | ⏳ Planned |
| File Integrity Monitoring     | Detect unauthorized file changes               | ⏳ Planned |
| Network Reconnaissance        | Study network discovery activity               | ⏳ Planned |
| PowerShell Monitoring         | Understand Windows command execution telemetry | ⏳ Planned |
| Persistence Detection         | Study common persistence indicators            | ⏳ Planned |
| Custom Detection Rules        | Build and test custom detections               | ⏳ Planned |
| Incident Response             | Practice SOC response workflow                 | ⏳ Planned |
| Telegram Alerting             | Send selected security alerts to Telegram      | ⏳ Planned |

> Attack simulations will only target intentionally created lab systems.

---

## 🔎 Investigation Methodology

Each completed investigation will be documented using the following structure:

```text
1. Alert / Trigger
2. Initial Triage
3. Affected Host
4. Source IP / Entity
5. Timeline
6. Relevant Logs
7. Indicators of Compromise
8. Detection Rule
9. MITRE ATT&CK Mapping
10. Investigation Findings
11. Scope Assessment
12. Response
13. Root Cause
14. Recommendations
15. Lessons Learned
```

---

## 📊 SOC Analyst Learning Goals

This project is designed to develop practical skills in:

* SOC monitoring
* Alert triage
* SIEM operations
* XDR concepts
* Log analysis
* Windows security monitoring
* Linux security monitoring
* Threat detection
* Threat hunting
* Incident investigation
* Incident response
* Detection engineering
* MITRE ATT&CK
* Security automation
* Security documentation

---

## 📂 Repository Structure

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
│   └── web/
│
├── detections/
│   ├── custom-rules/
│   └── detection-notes.md
│
├── docs/
│   ├── setup/
│   ├── learning-notes/
│   └── troubleshooting/
│
├── investigations/
│   ├── 001-ssh-bruteforce/
│   ├── 002-suspicious-process/
│   └── ...
│
├── response/
│   ├── incident-response/
│   └── active-response/
│
├── scripts/
│   ├── python/
│   ├── powershell/
│   └── bash/
│
├── screenshots/
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

---

## 📈 Project Progress

### Environment

* [x] VirtualBox environment
* [x] Ubuntu VM
* [x] Ubuntu resources configured
* [x] Ubuntu disk expanded to 70 GB
* [x] Docker installed
* [x] Docker Compose installed

### GitHub & Documentation

* [x] GitHub repository created
* [x] Git installed
* [x] VS Code installed
* [x] GitHub connected with VS Code
* [x] Repository cloned locally
* [x] Repository structure created
* [x] `.gitignore` configured
* [x] First Git commit created
* [x] GitHub remote configured

### Wazuh

* [ ] Wazuh Docker deployment
* [ ] Wazuh Dashboard
* [ ] Wazuh Manager
* [ ] Wazuh Indexer
* [ ] Wazuh agent enrollment
* [ ] Linux monitoring
* [ ] Windows monitoring
* [ ] Endpoint visibility

### Detection & Investigation

* [ ] First security alert
* [ ] First investigation
* [ ] MITRE ATT&CK mapping
* [ ] Custom detection rules
* [ ] Detection tuning
* [ ] Threat hunting
* [ ] Incident response

### Automation

* [ ] Telegram alerting
* [ ] Python automation
* [ ] API integration
* [ ] Security automation

---

## 🧠 Learning Approach

The project follows a continuous learning cycle:

```text
Learn
  ↓
Build
  ↓
Generate Security Event
  ↓
Detect
  ↓
Investigate
  ↓
Respond
  ↓
Document
  ↓
Improve Detection
  ↓
Repeat
```

The goal is not only to generate alerts, but to understand **why the alert happened, how the evidence supports the conclusion, and how a SOC analyst should respond.**

---

## 🔐 Lab Safety

This project is conducted in a controlled security laboratory.

All security testing will be performed only against intentionally created and authorized lab systems.

No unauthorized:

* Systems
* Networks
* Accounts
* Applications
* Production environments
* Third-party infrastructure

will be targeted.

Sensitive information such as passwords, API keys, tokens, private keys, and personal credentials will not be stored in this repository.

---

## 📚 Documentation Philosophy

Every major lab activity will be documented with:

* Objective
* Environment
* Configuration
* Commands
* Expected results
* Actual results
* Screenshots
* Detection analysis
* Investigation
* Lessons learned

The documentation will focus on understanding **both the offensive activity and the defensive detection/response process**.

---

## 🚧 Project Status

**Status:** 🚧 Active Development

This repository will continuously evolve as new SOC capabilities, detection techniques, investigations, and automation are added.

---

## 👨‍💻 Project Focus

**Security Operations Center | SIEM | XDR | Threat Detection | Incident Response | Detection Engineering | Security Automation**

---

⭐ This project is built for continuous hands-on learning and professional SOC skill development.
