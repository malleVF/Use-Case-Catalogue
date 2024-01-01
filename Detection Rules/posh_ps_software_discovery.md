---
title: "Detected Windows Software Discovery - PowerShell"
status: "test"
created: "2020/10/16"
last_modified: "2022/12/02"
tags: [discovery, t1518, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Detected Windows Software Discovery - PowerShell

### Description

Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.

```yml
title: Detected Windows Software Discovery - PowerShell
id: 2650dd1a-eb2a-412d-ac36-83f06c4f2282
status: test
description: Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1518/T1518.md
    - https://github.com/harleyQu1nn/AggressorScripts # AVQuery.cna
author: Nikita Nazarov, oscd.community
date: 2020/10/16
modified: 2022/12/02
tags:
    - attack.discovery
    - attack.t1518
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            # Example: Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize
            - 'get-itemProperty'
            - '\software\'
            - 'select-object'
            - 'format-table'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium

```