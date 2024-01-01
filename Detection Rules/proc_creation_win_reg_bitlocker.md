---
title: "Suspicious Reg Add BitLocker"
status: "test"
created: "2021/11/15"
last_modified: "2022/09/09"
tags: [impact, t1486, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Reg Add BitLocker

### Description

Detects suspicious addition to BitLocker related registry keys via the reg.exe utility

```yml
title: Suspicious Reg Add BitLocker
id: 0e0255bf-2548-47b8-9582-c0955c9283f5
status: test
description: Detects suspicious addition to BitLocker related registry keys via the reg.exe utility
references:
    - https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/
author: frack113
date: 2021/11/15
modified: 2022/09/09
tags:
    - attack.impact
    - attack.t1486
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'REG'
            - 'ADD'
            - '\SOFTWARE\Policies\Microsoft\FVE'
            - '/v'
            - '/f'
        CommandLine|contains:
            - 'EnableBDEWithNoTPM'
            - 'UseAdvancedStartup'
            - 'UseTPM'
            - 'UseTPMKey'
            - 'UseTPMKeyPIN'
            - 'RecoveryKeyMessageSource'
            - 'UseTPMPIN'
            - 'RecoveryKeyMessage'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
