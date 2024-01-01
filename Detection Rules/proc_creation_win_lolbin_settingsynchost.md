---
title: "Using SettingSyncHost.exe as LOLBin"
status: "test"
created: "2020/02/05"
last_modified: "2021/11/27"
tags: [execution, defense_evasion, t1574_008, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Using SettingSyncHost.exe as LOLBin

### Description

Detects using SettingSyncHost.exe to run hijacked binary

```yml
title: Using SettingSyncHost.exe as LOLBin
id: b2ddd389-f676-4ac4-845a-e00781a48e5f
status: test
description: Detects using SettingSyncHost.exe to run hijacked binary
references:
    - https://www.hexacorn.com/blog/2020/02/02/settingsynchost-exe-as-a-lolbin
author: Anton Kutepov, oscd.community
date: 2020/02/05
modified: 2021/11/27
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1574.008
logsource:
    category: process_creation
    product: windows
detection:
    system_utility:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    parent_is_settingsynchost:
        ParentCommandLine|contains|all:
            - 'cmd.exe /c'
            - 'RoamDiag.cmd'
            - '-outputpath'
    condition: not system_utility and parent_is_settingsynchost
fields:
    - TargetFilename
    - Image
falsepositives:
    - Unknown
level: high

```