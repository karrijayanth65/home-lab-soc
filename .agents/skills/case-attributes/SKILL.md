---
name: case-attributes
description: Create, review, or standardize SOC and cybersecurity investigation cases using a consistent set of case metadata, entities, evidence, constraints, detection details, analysis, verdict, and closure fields. Use when documenting a new SIEM, EDR, Windows, Linux, network, cloud, malware, phishing, authentication, or incident-response case; converting raw alerts into investigation documentation; identifying missing investigation attributes; or preparing a GitHub-ready SOC portfolio case.
---

# Case Attributes

Build each investigation as a defensible record of what happened, how it was detected, what the evidence proves, and what remains uncertain. Adapt the fields to the available telemetry; do not invent missing values.

## Gather the case attributes

Capture the following groups. Mark unavailable values as `Not available` and explain material visibility gaps under **Constraints and limitations**.

### 1. Case metadata

- Case ID and descriptive title
- Case type or alert category
- Date and time, including timezone
- Analyst or case owner when provided
- Environment: lab, test, or production
- Severity, priority, status, and confidence
- Investigation objective and scope

### 2. Detection metadata

- Detection source: SIEM, EDR, IDS/IPS, firewall, email gateway, cloud service, or endpoint log
- Product and data source
- Alert or detection name
- Rule ID, rule name, and rule severity
- Event ID, log channel, provider, decoder, index, and agent ID when applicable
- First seen, last seen, alert time, and ingestion time when available
- Detection logic, threshold, or matching condition

### 3. Core dimensions and entities

- Source and destination IP addresses
- Source and destination ports
- Protocol, application, and direction
- Hostname, device name, operating system, and asset role
- Username, account domain, SID, session, and authentication type
- Process name, PID, parent process, command line, and executable path
- File name, path, extension, size, hash, and signature status
- URL, domain, email address, sender, recipient, and message identifiers
- Cloud account, tenant, subscription, resource, region, and identity when relevant
- Share name, object name, registry key, service, task, or other affected resource

### 4. Activity and timeline

- Initial trigger
- Ordered sequence of actions
- Commands, operations, requests, and access types
- Authentication successes or failures
- Relevant timestamps and duration
- Related alerts or events
- Discovery, access, execution, persistence, privilege change, lateral movement, collection, or exfiltration behavior

### 5. Evidence

- Raw event fields and representative log excerpts
- Screenshots with meaningful captions
- Command output and query results
- Packet captures or network-flow evidence
- File hashes, malware-analysis results, or sandbox evidence
- Detection rule or query used
- Architecture or evidence-flow diagram when useful
- Links or paths to supporting artifacts

Keep observation separate from interpretation. State what each artifact proves and avoid treating a screenshot count as evidence quality.

### 6. Security context

- Affected asset and its business purpose
- Asset criticality and data sensitivity when known
- MITRE ATT&CK tactic, technique, and sub-technique when supported
- Indicators of compromise and observables
- Expected baseline versus observed behavior
- Potential impact and realistic attack hypothesis
- Related threat intelligence, vulnerabilities, or known tools when evidence supports the link

### 7. Constraints and limitations

- Missing, disabled, delayed, or incomplete logs
- Data-retention or timestamp limitations
- NAT, VPN, proxy, shared-account, or attribution limits
- Encryption or insufficient endpoint/network visibility
- Lab-generated actions, controlled accounts, and test resources
- Detection-rule coverage gaps
- Evidence that was unavailable or could not be validated
- Conclusions the available evidence cannot support

### 8. Analysis and verdict

- Evidence-based findings
- Benign and malicious explanations considered
- Classification: true positive, benign positive, false positive, or inconclusive
- Authorization: authorized, unauthorized, or unknown
- Scope: affected users, hosts, files, accounts, and services
- Confidence level with a short reason
- Root cause when established
- Clear analyst conclusion

Do not label an event malicious solely because a detection rule fired. Correlate identity, endpoint, network, time, asset, and behavior evidence before reaching a verdict.

### 9. Response and closure

- Containment, eradication, and recovery actions
- Accounts, hosts, indicators, or files blocked or isolated
- Escalation and notification details when provided
- Detection-tuning or logging recommendations
- Preventive security improvements
- Follow-up actions and owners when known
- Closure reason, status, and closure timestamp

## Produce the investigation

Use this order unless the user's existing repository has a required structure:

1. Case header and metadata
2. Executive summary
3. Investigation objective and scope
4. Environment or architecture
5. Detection details
6. Entities and key attributes
7. Timeline and evidence
8. Analysis and correlation
9. MITRE ATT&CK mapping
10. Constraints and limitations
11. Analyst verdict
12. Response and recommendations
13. Evidence index and case closure

Write the executive summary in three to five plain sentences covering the trigger, principal entities, key evidence, detection result, and verdict. Preserve exact technical values in tables or code blocks. Explain each value's investigative meaning in prose.

## Quality checks

Before finalizing:

- Confirm that timestamps include a timezone or state that it is unknown.
- Confirm that source, destination, user, asset, process, file, and network fields are internally consistent.
- Distinguish event time from ingestion and alert time.
- Ensure every conclusion points to evidence.
- State whether the activity was simulated, authorized, or observed in production.
- Avoid claiming compromise, attribution, or data loss without supporting evidence.
- Record missing telemetry and rule limitations.
- Remove secrets, passwords, tokens, and unnecessary personal data.
- End with a concise closure statement containing the activity, affected resource, detection path, verdict, and confidence.

## Minimum case template

```markdown
# Case [ID] — [Descriptive title]

> **Case type:** [Category]
> **Detection:** [Product / rule]
> **Severity:** [Value]
> **Status:** [Open / Investigating / Closed]
> **Environment:** [Lab / Test / Production]
> **Time range:** [Start–end with timezone]

## Executive Summary
[Trigger, main entities, evidence, detection result, and verdict.]

## Objective and Scope
[Question investigated and boundaries.]

## Detection Details
| Attribute | Value |
|---|---|
| Alert / Rule | |
| Event / Data source | |
| Detection time | |
| Logic / Threshold | |

## Entities and Dimensions
| Entity | Value | Investigative relevance |
|---|---|---|
| Source | | |
| Destination | | |
| User / Identity | | |
| Host / Asset | | |
| Process / File / URL | | |
| Protocol / Port | | |

## Timeline and Evidence
| Time | Activity | Evidence | Interpretation |
|---|---|---|---|
| | | | |

## Analysis and MITRE ATT&CK
[Correlation, baseline comparison, hypotheses, tactic and technique mapping.]

## Constraints and Limitations
[Missing telemetry and conclusions that cannot be supported.]

## Analyst Verdict
- **Classification:**
- **Authorization:**
- **Scope:**
- **Confidence:**
- **Reasoning:**

## Response and Recommendations
[Completed and proposed actions.]

## Case Closure
[Activity, affected resource, detection path, verdict, and confidence.]
```

