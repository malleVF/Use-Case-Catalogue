---
title: "Potential AutoLogger Sessions Tampering"
status: "experimental"
created: "2022/08/01"
last_modified: "2023/08/17"
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential AutoLogger Sessions Tampering

### Description

Detects tampering with autologger trace sessions which is a technique used by attackers to disable logging

```yml
title: Potential AutoLogger Sessions Tampering
id: f37b4bce-49d0-4087-9f5b-58bffda77316
status: experimental
description: Detects tampering with autologger trace sessions which is a technique used by attackers to disable logging
references:
    - https://twitter.com/MichalKoczwara/status/1553634816016498688
    - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
    - https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/01
modified: 2023/08/17
tags:
    - attack.defense_evasion
logsource:
    category: registry_set
    product: windows
detection:
    selection_main:
        TargetObject|contains: '\System\CurrentControlSet\Control\WMI\Autologger\'
    selection_values:
        TargetObject|contains: # We only care about some autologger to avoid FP. Add more if you need
            - '\EventLog-'
            - '\Defender'
        TargetObject|endswith:
            - '\Enable'
            - '\Start'
        Details: DWORD (0x00000000)
    filter_wevtutil:
        Image: 'C:\Windows\system32\wevtutil.exe'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Unknown
level: high

```