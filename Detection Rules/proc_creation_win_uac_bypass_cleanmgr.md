---
title: "UAC Bypass Using Disk Cleanup"
status: "test"
created: "2021/08/30"
last_modified: "2022/10/09"
tags: [defense_evasion, privilege_escalation, t1548_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## UAC Bypass Using Disk Cleanup

### Description

Detects the pattern of UAC Bypass using scheduled tasks and variable expansion of cleanmgr.exe (UACMe 34)

```yml
title: UAC Bypass Using Disk Cleanup
id: b697e69c-746f-4a86-9f59-7bfff8eab881
status: test
description: Detects the pattern of UAC Bypass using scheduled tasks and variable expansion of cleanmgr.exe (UACMe 34)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021/08/30
modified: 2022/10/09
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|endswith: '"\system32\cleanmgr.exe /autoclean /d C:'
        ParentCommandLine: 'C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high

```
