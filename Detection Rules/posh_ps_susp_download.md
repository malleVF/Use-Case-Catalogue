---
title: "Suspicious PowerShell Download - Powershell Script"
status: "test"
created: "2017/03/05"
last_modified: "2022/12/02"
tags: [execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious PowerShell Download - Powershell Script

### Description

Detects suspicious PowerShell download command

```yml
title: Suspicious PowerShell Download - Powershell Script
id: 403c2cc0-7f6b-4925-9423-bfa573bed7eb
related:
    - id: 65531a81-a694-4e31-ae04-f8ba5bc33759
      type: derived
status: test
description: Detects suspicious PowerShell download command
author: Florian Roth (Nextron Systems)
date: 2017/03/05
modified: 2022/12/02
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    webclient:
        ScriptBlockText|contains: 'System.Net.WebClient'
    download:
        ScriptBlockText|contains:
            - '.DownloadFile('
            - '.DownloadString('
    condition: webclient and download
falsepositives:
    - PowerShell scripts that download content from the Internet
level: medium

```
