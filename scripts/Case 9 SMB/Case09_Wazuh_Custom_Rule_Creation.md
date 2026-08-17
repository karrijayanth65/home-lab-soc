# Wazuh Custom Rule Creation --- Case 09 SMB File Share Access

## Purpose

This document records the procedure used in the SOC lab to create,
validate, load, and verify a custom Wazuh rule for Windows Security
Event ID **5145**.

The rule detects successful Windows Detailed File Share access events
and generates a Level 8 Wazuh alert.

## Detection Flow

``` text
Kali Linux
   |
   | Authenticated SMB file access
   v
Windows 11
   |
   | Security Event ID 5145
   v
Wazuh Agent 002
   |
   | Windows EventChannel
   v
Wazuh Manager (Docker)
   |
   | Custom Rule 100145
   v
Wazuh Level 8 Alert
```

## 1. Confirm Windows 5145 Collection

Windows Security auditing must generate Event ID 5145.

In this lab, the Wazuh Windows agent originally excluded Event ID 5145
from its Security event collection query. The exclusion was removed
from:

``` text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

After the change, the Wazuh agent was restarted.

Do not remove unrelated exclusions unnecessarily.

## 2. Confirm the Wazuh Custom Rules Directory

The Wazuh manager was running inside Docker.

The relevant manager configuration was:

``` xml
<ruleset>
  <decoder_dir>ruleset/decoders</decoder_dir>
  <rule_dir>ruleset/rules</rule_dir>

  <!-- User-defined ruleset -->
  <decoder_dir>etc/decoders</decoder_dir>
  <rule_dir>etc/rules</rule_dir>
</ruleset>
```

Therefore custom rules are loaded from:

``` text
/var/ossec/etc/rules/
```

inside the manager container.

## 3. Inspect Existing Custom Rules

The existing custom rules were inspected with:

``` bash
docker exec single-node-wazuh.manager-1 sh -c 'cat /var/ossec/etc/rules/local_rules.xml'
```

The lab already had a valid Case 7 custom rule, confirming the expected
XML structure.

## 4. Check for an Existing 5145 Rule

The installed Windows Security rules were searched:

``` bash
docker exec single-node-wazuh.manager-1 sh -c 'grep -RniE "eventID|shareName|5145" /var/ossec/ruleset/decoders /var/ossec/ruleset/rules/0580-win-security_rules.xml | head -40'
```

No dedicated built-in 5145 detection rule was found.

Wazuh's Windows Security rules use:

``` text
win.system.eventID
```

for Windows Event IDs.

## 5. Identify the Parent Audit Rule

The installed Windows Security rules showed:

``` xml
<rule id="60103" level="0">
  <if_sid>60001</if_sid>
  <field name="win.system.severityValue">^AUDIT_SUCCESS$|^success$</field>
  <description>Windows audit success event</description>
  <options>no_full_log</options>
</rule>
```

Event ID 5145 in this lab is an Audit Success event, so Rule 60103 was
used as the parent.

## 6. Final Custom Rule

The final Case 09 rule was:

``` xml
<group name="windows,smb,case9,">

  <rule id="100145" level="8">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^5145$</field>
    <description>Case 09 - Windows Detailed File Share Access - Event ID 5145</description>
    <group>network_share_access,windows_security,smb,</group>
  </rule>

</group>
```

### Rule logic

``` text
Windows Audit Success (60103)
        +
Event ID 5145
        ↓
Custom Rule 100145
        ↓
Level 8 alert
```

The rule intentionally matches Event ID 5145 generally rather than
restricting the rule to the lab's `Case9-SMB` share.

## 7. Rule ID Issue

The first attempted rule ID was:

``` text
1005145
```

The installed Wazuh version rejected it:

``` text
ERROR: Invalid rule id: 1005145. Must be integer (max 6 digits)
```

The final rule ID was changed to:

``` text
100145
```

## 8. Create the Rule

The final rule file was created at:

``` text
/var/ossec/etc/rules/case9-smb-rules.xml
```

The lab used:

``` bash
docker exec single-node-wazuh.manager-1 sh -c 'printf "%s\n" "<group name=\"windows,smb,case9,\">" "  <rule id=\"100145\" level=\"8\">" "    <if_sid>60103</if_sid>" "    <field name=\"win.system.eventID\">^5145$</field>" "    <description>Case 09 - Windows Detailed File Share Access - Event ID 5145</description>" "    <group>network_share_access,windows_security,smb,</group>" "  </rule>" "</group>" > /var/ossec/etc/rules/case9-smb-rules.xml'
```

## 9. Validate Before Restarting

Always validate the manager configuration before restarting:

``` bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t; echo "EXIT_CODE=$?"
```

Successful validation:

``` text
EXIT_CODE=0
```

If validation fails, do not restart the manager. Fix the reported
rule/configuration error first.

## 10. Confirm the Agent-to-Manager Pipeline

Existing alerts from Windows agent `002` were checked:

``` bash
docker exec single-node-wazuh.manager-1 sh -c 'grep "\"agent\":{\"id\":\"002\"" /var/ossec/logs/alerts/alerts.json | tail -3'
```

This confirmed that Windows EventChannel events were reaching the
manager and being decoded with:

``` text
windows_eventchannel
```

## 11. Load the Rule

After successful validation:

``` bash
docker restart single-node-wazuh.manager-1
```

## 12. Generate the SMB Test Event

From Kali:

``` bash
smbclient //192.168.56.105/Case9-SMB -U 'jais_test_pc'
```

At the SMB prompt:

``` text
get Case9-Test-Document.txt
```

Then:

``` text
quit
```

This generated Windows Security Event ID 5145.

## 13. Verify the Custom Rule

The resulting Wazuh alert was checked with:

``` bash
docker exec single-node-wazuh.manager-1 sh -c 'grep "\"agent\":{\"id\":\"002\"" /var/ossec/logs/alerts/alerts.json | grep -E "\"id\":\"100145\"|5145|Case 09" | tail -5'
```

The successful alert showed:

``` text
Rule ID:       100145
Level:         8
Agent:         Windows11
Agent ID:      002
Event ID:      5145
Decoder:       windows_eventchannel
Source IP:     192.168.56.106
Share:         Case9-SMB
Target:        Case9-Test-Document.txt
Fired times:   1
```

## 14. Evidence Files

### Kali SMB File Read

``` text
PS_10_Case9_Kali_SMB_File_Read.png
```

Shows the authenticated SMB client reading the test file.

### Windows Security Event 5145

``` text
PS_15_Case9_Windows_Security_5145_Source_and_Access.png
```

Shows Event ID 5145, source address, account, share, target file, and
access information.

### Wazuh Detection

``` text
PS_16_Case9_Wazuh_Rule_100145_SMB_5145_Detection.png
```

Shows Rule 100145, Level 8, Windows11 agent, and the Case 09 detection.

## 15. Final Detection Chain

``` text
Authenticated SMB file read
        ↓
Windows Security Event 5145
        ↓
Wazuh Agent 002
        ↓
windows_eventchannel decoder
        ↓
Rule 60103 — Windows Audit Success
        ↓
Rule 100145 — Event ID 5145
        ↓
Level 8 Wazuh Alert
        ↓
Wazuh Dashboard
```

## 16. Troubleshooting Lessons

### Dashboard returned error 1113

The Wazuh Dashboard custom-rule editor repeatedly returned:

``` text
Could not upload rule (1113) - XML syntax error
```

The manager configuration itself was then tested:

``` bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t; echo "EXIT_CODE=$?"
```

The manager returned:

``` text
EXIT_CODE=0
```

The rule was therefore created directly in the configured custom-rule
directory instead of continuing to retry the Dashboard editor.

### Invalid rule ID

The initial ID:

``` text
1005145
```

was rejected because the installed Wazuh version requires a maximum of
six digits.

Final ID:

``` text
100145
```

### Archives did not contain the event

The manager configuration showed:

``` xml
<logall>no</logall>
<logall_json>no</logall_json>
```

Therefore `archives.json` was not expected to contain every received
event. It was not necessary to enable `logall` for this case.

## 17. Persistence Note for Docker

The rule currently exists inside the running Wazuh manager container:

``` text
/var/ossec/etc/rules/case9-smb-rules.xml
```

Because the manager is containerized, verify that this file is backed by
the Docker deployment's persistent configuration/volume before
recreating or rebuilding the container.

A container recreation that does not preserve `/var/ossec/etc/rules/`
could remove the custom rule.

## Result

**Case 09 custom Wazuh detection: VERIFIED**

``` text
Windows Event ID 5145
        ↓
Custom Rule 100145
        ↓
Level 8
        ↓
Wazuh alert
```

The rule was successfully triggered by a real authenticated SMB
file-read operation in the lab.
