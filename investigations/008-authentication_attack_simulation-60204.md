# Case 08 — Authentication Attack Simulation — Wazuh Rule 60204

> **Investigation type:** Windows authentication failure / brute-force simulation  
> **Platform:** Windows 11 endpoint monitored by Wazuh  
> **Wazuh agent:** `002` (`Windows11`)  
> **Primary detection:** Rule `60204` — **Multiple Windows Logon Failures**  
> **Individual detection:** Rule `60122` — **Logon Failure - Unknown user or bad password**  
> **Windows event:** `4625` — failed logon  
> **MITRE ATT&CK:** `T1110` — Brute Force  
> **Status:** **Completed**  
> **Environment:** Controlled SOC laboratory

---

## 1. Investigation Objective

This case validates the complete defensive telemetry and correlation path for repeated Windows authentication failures.

The investigation verifies that repeated authentication failures are:

1. generated intentionally on the Windows endpoint;
2. recorded by Windows Security as Event ID `4625`;
3. ingested by the Wazuh agent;
4. detected individually by Wazuh Rule `60122`;
5. correlated when the configured threshold is reached; and
6. promoted to a higher-severity Wazuh alert through Rule `60204`.

The activity was intentionally generated inside the SOC laboratory. It demonstrates the detection capability and evidence chain rather than a real-world compromise.

---

## 2. Case Architecture

The following architecture represents the investigation environment and the telemetry path used in Case 08.

![Case 08 Authentication Attack Simulation Architecture](../architecture/Case%208%20-%20Authentication%20Attack%20Simulation/Authentication%20Attack%20Simulation%20Architecture.png)

**Architecture artifact:**  
`architecture/Case 8 - Authentication Attack Simulation/Authentication Attack Simulation Architecture.png`

### Architecture interpretation

The investigation follows this general path:

```text
Controlled authentication-failure activity
                |
                v
        Windows 11 endpoint
        Security Event 4625
                |
                v
          Wazuh Agent 002
                |
                v
         Wazuh Manager
                |
        +-------+-------+
        |               |
        v               v
     Rule 60122      Correlation
   Individual          logic
     failure             |
                         v
                     Rule 60204
                 Multiple Windows
                   Logon Failures
                         |
                         v
                   Level 10 alert
```

The architecture image is a learning/analysis aid. The screenshots and Wazuh rule evidence remain the authoritative case artifacts.

---

## 3. Detection Scenario

The simulated behavior was a sequence of failed Windows logon attempts.

| Item | Value |
|---|---|
| Windows event | `4625` |
| Event meaning | Failed logon / authentication failure |
| Individual Wazuh rule | `60122` |
| Individual rule description | `Logon Failure - Unknown user or bad password` |
| Correlation rule | `60204` |
| Correlation description | `Multiple Windows Logon Failures` |
| Correlation level | `10` |
| Frequency variable | `$MS_FREQ` |
| Configured `$MS_FREQ` | `8` |
| Timeframe | `240` seconds |
| Same-field correlation | `win.eventdata.ipAddress` |
| MITRE ATT&CK | `T1110` — Brute Force |
| MITRE tactic | Credential Access |

During the controlled test, repeated failures reached the configured correlation threshold and Wazuh generated Rule `60204`.

---

## 4. Evidence Chain

```text
Intentional failed Windows logons
                |
                v
Windows Security Event 4625
                |
                v
Wazuh ingestion
                |
                v
Rule 60122
"Logon Failure - Unknown user or bad password"
                |
                v
Repeated authentication failures
from the same source field
                |
                v
Rule 60204 correlation
"Multiple Windows Logon Failures"
                |
                v
Level 10 alert
                |
                v
MITRE ATT&CK T1110 — Brute Force
```

This chain is the central learning objective of the case.

---

# 5. Evidence 01 — Windows Event ID 4625

![Windows Event ID 4625 logon failures](../screenshots/Case%208/PS_01_Case8_Windows_4625_Logon_Failures.png)

**Artifact:** `PS_01_Case8_Windows_4625_Logon_Failures.png`

Windows Event Viewer showed intentionally generated authentication failures in the **Security** log.

Observed properties included:

- **Event ID:** `4625`
- **Keywords:** `Audit Failure`
- **Task Category:** `Logon`
- **Source:** Microsoft Windows Security Auditing

The initial failures were confirmed at the Windows endpoint before the Wazuh correlation stage.

### Evidence significance

This is the endpoint-side evidence.

It establishes that the authentication failures existed as Windows Security telemetry before Wazuh processed them. The Wazuh detection therefore has an observable endpoint source rather than being a manually fabricated SIEM event.

---

# 6. Evidence 02 — Wazuh Rule 60122

![Wazuh Rule 60122 logon failure detection](../screenshots/Case%208/PS_02_Case8_Wazuh_60122_Logon_Failures.png)

**Artifact:** `PS_02_Case8_Wazuh_60122_Logon_Failures.png`

Wazuh received the Windows authentication failures and generated:

- **Rule ID:** `60122`
- **Level:** `5`
- **Description:** `Logon Failure - Unknown user or bad password`

Multiple occurrences were observed in the Wazuh Events interface.

### Evidence significance

Rule `60122` is the **individual-event detection layer**.

It confirms that Wazuh can identify each Windows authentication failure as it arrives from the endpoint.

---

# 7. Evidence 03 — Wazuh Rule 60204 Correlation Alert

![Wazuh Rule 60204 multiple logon failures](../screenshots/Case%208/PS_03_Case8_Wazuh_60204_Multiple_Logon_Failures.png)

**Artifact:** `PS_03_Case8_Wazuh_60204_Multiple_Logon_Failures.png`

After repeated authentication failures were intentionally generated, Wazuh produced:

- **Rule ID:** `60204`
- **Level:** `10`
- **Description:** `Multiple Windows Logon Failures`

This is the **primary correlation result** for Case 08.

The observed progression was:

```text
Individual 4625 failures
        ↓
Rule 60122
        ↓
Repeated failures
        ↓
Rule 60204
        ↓
Level 10 alert
```

### Important distinction

Rule `60122` represents an individual authentication failure.

Rule `60204` represents a repeated-failure pattern that satisfied the configured correlation logic.

---

# 8. Evidence 04 — Rule 60204 Definition

![Wazuh Rule 60204 definition](../screenshots/Case%208/PS_04_Case8_Wazuh_Rule_60204_Definition.png)

**Artifact:** `PS_04_Case8_Wazuh_Rule_60204_Definition.png`

The Wazuh Rules interface identifies Rule `60204` as:

| Property | Value |
|---|---|
| Rule ID | `60204` |
| Description | `Multiple Windows Logon Failures` |
| Level | `10` |
| File | `0580-win-security_rules.xml` |
| Path | `ruleset/rules` |
| Groups | `authentication_failures`, `windows`, `windows_security` |
| Frequency | `$MS_FREQ` |
| Timeframe | `240` |
| If matched group | `authentication_failed` |
| Same field | `win.eventdata.ipAddress` |
| MITRE technique | `T1110` |
| MITRE tactic | Credential Access |

### Detection logic

The rule correlates authentication failures belonging to the `authentication_failed` group and uses:

```text
same_field = win.eventdata.ipAddress
```

The source IP is therefore part of the correlation condition.

---

# 9. Evidence 05 — Frequency and Threshold Definition

![Wazuh Rule 60204 frequency definition](../screenshots/Case%208/PS_05_Case8_Wazuh_Rule_60204_Frequency_Definition.png)

**Artifact:** `PS_05_Case8_Wazuh_Rule_60204_Frequency_Definition.png`

The Wazuh rule source provides the detailed correlation configuration.

Relevant definition:

```xml
<rule id="60204" level="10" frequency="$MS_FREQ" timeframe="240">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Multiple Windows Logon Failures</description>
    ...
    <mitre>
        <id>T1110</id>
    </mitre>
</rule>
```

The configured frequency variable is:

```xml
<var name="MS_FREQ">8</var>
```

Therefore, the lab configuration is:

- **Frequency:** `8`
- **Timeframe:** `240 seconds`
- **Correlation basis:** `authentication_failed`
- **Same source field:** `win.eventdata.ipAddress`

The controlled test reached the configured threshold and produced Rule `60204`.

---

# 10. Detection Validation

## Stage 1 — Individual authentication failures

A small number of failed logons were intentionally generated.

Windows captured Event ID `4625`.

Wazuh generated Rule `60122`:

```text
Logon Failure - Unknown user or bad password
```

This verified the basic endpoint-to-Wazuh telemetry path.

## Stage 2 — Repeated authentication failures

A larger sequence of authentication failures was intentionally generated.

The test reached the configured Rule `60204` frequency threshold.

Wazuh generated:

```text
Rule: 60204
Level: 10
Description: Multiple Windows Logon Failures
```

The alert was visible in the Wazuh Events interface.

## Stage 3 — Threshold confirmation

The Rule `60204` definition establishes that:

```text
MS_FREQ = 8
Timeframe = 240 seconds
Same field = win.eventdata.ipAddress
```

The test therefore validates both:

1. **the observed detection result**, and
2. **the configuration that explains why the result was generated**.

---

# 11. Why Rule 60204 Matters

A single failed login is not necessarily malicious.

Repeated authentication failures are more useful as a behavioral detection signal because they can indicate:

- password guessing;
- brute-force behavior;
- credential attacks;
- account enumeration attempts;
- misconfigured automated authentication.

The SOC principle demonstrated here is:

> **Individual events become more meaningful when they are correlated into behavior.**

Rule `60122` provides the individual failure detection, while Rule `60204` identifies the repeated-failure pattern.

---

# 12. MITRE ATT&CK Mapping

The Wazuh rule maps this behavior to:

| Field | Value |
|---|---|
| MITRE Technique | `T1110` |
| Technique Name | Brute Force |
| Tactic | Credential Access |

This mapping is part of the Wazuh rule evidence.

Because the activity was intentionally generated in a controlled laboratory, this case demonstrates **detection of brute-force-like behavior**, not proof of a real external attacker or malicious intent.

---

# 13. SOC Investigation Questions

## What happened?

Repeated Windows authentication failures were intentionally generated in the SOC lab.

## What did Windows observe?

Windows Security recorded Event ID `4625` authentication failures.

## What did Wazuh observe first?

Wazuh generated individual authentication-failure detections through Rule `60122`.

## What happened after repeated failures?

Wazuh correlated the repeated failures and generated Rule `60204` at Level `10`.

## Why did Rule 60204 fire?

The rule is configured to correlate matching `authentication_failed` events using the same `win.eventdata.ipAddress` field and the configured frequency/timeframe.

## What proves the detection?

The evidence set contains:

1. Windows Event ID `4625`
2. Wazuh Rule `60122`
3. Wazuh Rule `60204` alert
4. Rule `60204` definition
5. Rule frequency and `$MS_FREQ` configuration
6. Case architecture diagram

---

# 14. Evidence Inventory

| Artifact | Purpose | Evidence Layer |
|---|---|---|
| `PS_01_Case8_Windows_4625_Logon_Failures.png` | Windows authentication failures | Endpoint |
| `PS_02_Case8_Wazuh_60122_Logon_Failures.png` | Individual Wazuh failure detections | SIEM |
| `PS_03_Case8_Wazuh_60204_Multiple_Logon_Failures.png` | Correlated Level 10 detection | SIEM |
| `PS_04_Case8_Wazuh_Rule_60204_Definition.png` | Rule metadata and correlation logic | Detection engineering |
| `PS_05_Case8_Wazuh_Rule_60204_Frequency_Definition.png` | Threshold and `$MS_FREQ=8` proof | Detection engineering |
| `Authentication Attack Simulation Architecture.png` | Investigation architecture and telemetry flow | Architecture / learning |

---

# 15. Evidence Quality Assessment

## Primary evidence

The strongest detection evidence is:

- Windows Event ID `4625`
- Wazuh Rule `60122`
- Wazuh Rule `60204`

These establish the actual detection path.

## Supporting evidence

The Rule `60204` definition and frequency configuration explain **why** the higher-severity alert fired.

The architecture diagram explains the **system-level telemetry flow**, but it is not itself proof that an event occurred.

Together, the evidence establishes:

```text
WHAT happened
     +
WHERE it was observed
     +
HOW Wazuh detected it
     +
WHY the correlation alert fired
     +
HOW the investigation environment is connected
```

---

# 16. Investigation Limitations

This was a controlled SOC laboratory simulation.

Therefore:

- The authentication failures were intentionally generated.
- No real unauthorized account access was demonstrated.
- The evidence does not establish attacker attribution.
- The evidence does not establish malicious intent by itself.
- The test validates the configured detection path, not every possible authentication attack pattern.
- Rule `60204` firing should be interpreted in context with the source, account, timing, and surrounding endpoint activity during a real investigation.

These limitations should remain explicit in the case record.

---

# 17. Case Conclusion

**Case 08 — Authentication Attack Simulation — Rule 60204 is complete.**

The lab successfully demonstrated the defensive detection chain:

```text
Windows Security Event 4625
        ↓
Wazuh ingestion
        ↓
Rule 60122
"Logon Failure - Unknown user or bad password"
        ↓
Repeated failures from the same source
        ↓
Rule 60204
"Multiple Windows Logon Failures"
        ↓
Level 10
        ↓
MITRE T1110 — Brute Force
```

The evidence is sufficient to close the investigation without generating additional authentication failures.

---

# 18. Final Case Status

| Validation item | Status |
|---|---|
| Windows Event ID 4625 captured | ✅ |
| Individual Wazuh detection verified | ✅ |
| Rule 60122 verified | ✅ |
| Repeated authentication failures generated | ✅ |
| Rule 60204 triggered | ✅ |
| Level 10 alert observed | ✅ |
| Rule definition documented | ✅ |
| Frequency/timeframe documented | ✅ |
| `$MS_FREQ=8` documented | ✅ |
| Same-field correlation documented | ✅ |
| MITRE T1110 mapping documented | ✅ |
| Architecture documented | ✅ |
| Screenshots preserved | ✅ |
| Investigation complete | ✅ |

---

# 19. Repository Evidence Structure

```text
home-lab-soc-1/
├── investigations/
│   └── 008-authentication_attack_simulation-60204.md
│
├── architecture/
│   └── Case 8 - Authentication Attack Simulation/
│       └── Authentication Attack Simulation Architecture.png
│
└── screenshots/
    └── Case 8/
        ├── PS_01_Case8_Windows_4625_Logon_Failures.png
        ├── PS_02_Case8_Wazuh_60122_Logon_Failures.png
        ├── PS_03_Case8_Wazuh_60204_Multiple_Logon_Failures.png
        ├── PS_04_Case8_Wazuh_Rule_60204_Definition.png
        └── PS_05_Case8_Wazuh_Rule_60204_Frequency_Definition.png
```

All screenshot references are repository-relative so the Markdown should render correctly when viewed from:

```text
investigations/008-authentication_attack_simulation-60204.md
```

The architecture reference is also repository-relative and is intentionally kept separate from the evidentiary screenshots.

---

# 20. Case Closure Statement

> **Case 08 closed:** A controlled sequence of Windows authentication failures was successfully captured as Event ID `4625`, detected individually by Wazuh Rule `60122`, and correlated by Wazuh Rule `60204` at Level `10` after the configured threshold was reached. The rule configuration, threshold, same-field correlation logic, MITRE mapping, architecture, and resulting alert were preserved as case evidence.

---

## Learning Outcome

This case demonstrates a foundational SOC detection-engineering workflow:

```text
Endpoint activity
      ↓
Raw security telemetry
      ↓
SIEM ingestion
      ↓
Individual event detection
      ↓
Behavioral correlation
      ↓
Higher-severity alert
      ↓
MITRE ATT&CK mapping
      ↓
Evidence preservation
      ↓
Investigation closure
```

The important lesson is that a SOC does not rely on a single log entry alone. The investigation becomes stronger when endpoint evidence, individual detections, correlation logic, alert output, configuration evidence, and system architecture are connected into one defensible evidence chain.
