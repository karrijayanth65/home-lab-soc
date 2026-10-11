# Rebuilt-lab replay and evidence collection

Use this checklist only on the authorized isolated replacement lab. It is a future validation procedure; the commands were not run on a Windows endpoint during the offline capstone.

## Preparation

1. Snapshot the Windows target and establish a working administrative recovery channel.
2. Confirm time synchronization and record UTC offset on source, endpoint and SIEM.
3. Enable appropriate Security auditing and Sysmon collection; confirm fresh events arrive in Wazuh before starting.
4. Prepare an inert Base64 text fixture and a harmless health-check task action. Use a dedicated test account and approved WinRM source.
5. Record host, account, source address, exact commands and operator authorization. Do not assume fixture values match the replacement environment.

## Read-only investigation examples

Run locally on the target with permission to read Security logs. Adjust the time range to the real exercise and save original events as well as these display views.

```powershell
$from = Get-Date '2026-10-12T10:00:00Z'
$until = Get-Date '2026-10-12T13:00:00Z'

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624, 4698
    StartTime = $from
    EndTime = $until
} | Select-Object TimeCreated, Id, RecordId, Message

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
    StartTime = $from
    EndTime = $until
} | Select-Object TimeCreated, Id, RecordId, Message

Get-ScheduledTask -TaskName 'SOC-Lab-HealthCheck' |
    Select-Object TaskName, TaskPath, State, Actions, Principal, Triggers

Export-ScheduledTask -TaskName 'SOC-Lab-HealthCheck'
Get-FileHash -LiteralPath 'C:\Lab\decoded.txt' -Algorithm SHA256
```

Missing task or file errors are investigative results, not permission to declare cleanup successful. Compare original records, task history and earlier inventories. These examples do not delete tasks, quarantine files, isolate the system or modify accounts.

## Evidence acquisition and response

- Preserve EVTX, Wazuh event/alert exports, task XML, file copies and process/network state. Record collectors, exact collection times and source locations.
- Confirm the complete chain with Process GUID and Logon ID where possible. Verify task creation success separately from command execution.
- Record authorization and business impact before choosing containment. If the exercise is benign, record a benign positive rather than manufacture a malicious verdict.
- Perform approved response steps only after preservation; collect separate proof for every modeled gate in the capstone.
- Check task absence, artifact disposition, account/session control, service function and live SIEM ingestion.
- Observe the risk-appropriate period and relevant task trigger, hunt all accessible targets, obtain owner approval and document gaps.

## Replacement acceptance

Add captured artifacts alongside the fixtures, update their provenance and manifest, then rerun integrity and correlation tests. An offline test report alone does not replace live alert or recovery evidence. Preserve the existing fixture suite as a regression test when translating the analytic into Wazuh.
