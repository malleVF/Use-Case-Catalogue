---
title: "PUA - NSudo Execution"
status: "experimental"
created: "2022/01/24"
last_modified: "2023/02/13"
tags: [execution, t1569_002, s0029, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PUA - NSudo Execution

### Description

Detects the use of NSudo tool for command execution

```yml
title: PUA - NSudo Execution
id: 771d1eb5-9587-4568-95fb-9ec44153a012
status: experimental
description: Detects the use of NSudo tool for command execution
references:
    - https://nsudo.m2team.org/en-us/
    - https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali
date: 2022/01/24
modified: 2023/02/13
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\NSudo.exe'
              - '\NSudoLC.exe'
              - '\NSudoLG.exe'
        - OriginalFileName:
              - 'NSudo.exe'
              - 'NSudoLC.exe'
              - 'NSudoLG.exe'
    selection_cli:
        CommandLine|contains:
            # Covers Single/Double dash "-"/"--" + ":"
            - '-U:S ' # System
            - '-U:T ' # Trusted Installer
            - '-U:E ' # Elevated
            - '-P:E ' # Enable All Privileges
            - '-M:S ' # System Integrity
            - '-M:H ' # High Integrity
            # Covers Single/Double dash "-"/"--" + "="
            - '-U=S '
            - '-U=T '
            - '-U=E '
            - '-P=E '
            - '-M=S '
            - '-M=H '
            - '-ShowWindowMode:Hide'
    condition: all of selection_*
falsepositives:
    - Legitimate use by administrators
level: high

```
