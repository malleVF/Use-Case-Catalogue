---
title: "PowerShell Write-EventLog Usage"
status: "test"
created: "2022/08/16"
last_modified: ""
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PowerShell Write-EventLog Usage

### Description

Detects usage of the "Write-EventLog" cmdlet with 'RawData' flag. The cmdlet can be levreage to write malicious payloads to the EventLog and then retrieve them later for later use

```yml
title: PowerShell Write-EventLog Usage
id: 35f41cd7-c98e-469f-8a02-ec4ba0cc7a7e
status: test
description: Detects usage of the "Write-EventLog" cmdlet with 'RawData' flag. The cmdlet can be levreage to write malicious payloads to the EventLog and then retrieve them later for later use
references:
    - https://www.blackhillsinfosec.com/windows-event-logs-for-red-teams/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/16
tags:
    - attack.defense_evasion
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Write-EventLog'
            - '-RawData '
    condition: selection
falsepositives:
    - Legitimate applications writing events via this cmdlet. Investigate alerts to determine if the action is benign
level: medium

```