---
title: "Whoami.EXE Execution From Privileged Process"
status: "experimental"
created: "2022/01/28"
last_modified: "2023/12/04"
tags: [privilege_escalation, discovery, t1033, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Whoami.EXE Execution From Privileged Process

### Description

Detects the execution of "whoami.exe" by privileged accounts that are often abused by threat actors

```yml
title: Whoami.EXE Execution From Privileged Process
id: 79ce34ca-af29-4d0e-b832-fc1b377020db
related:
    - id: 80167ada-7a12-41ed-b8e9-aa47195c66a1
      type: obsoletes
status: experimental
description: Detects the execution of "whoami.exe" by privileged accounts that are often abused by threat actors
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://nsudo.m2team.org/en-us/
author: Florian Roth (Nextron Systems), Teymur Kheirkhabarov
date: 2022/01/28
modified: 2023/12/04
tags:
    - attack.privilege_escalation
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName: 'whoami.exe'
        - Image|endswith: '\whoami.exe'
    selection_user:
        User|contains:
            - 'AUTHORI'
            - 'AUTORI'
            - 'TrustedInstaller'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
