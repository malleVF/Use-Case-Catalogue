---
title: "Non-privileged Usage of Reg or Powershell"
status: "test"
created: "2020/10/05"
last_modified: "2022/07/07"
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Non-privileged Usage of Reg or Powershell

### Description

Search for usage of reg or Powershell by non-privileged users to modify service configuration in registry

```yml
title: Non-privileged Usage of Reg or Powershell
id: 8f02c935-effe-45b3-8fc9-ef8696a9e41d
status: test
description: Search for usage of reg or Powershell by non-privileged users to modify service configuration in registry
references:
    - https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-20-638.jpg
author: Teymur Kheirkhabarov (idea), Ryan Plas (rule), oscd.community
date: 2020/10/05
modified: 2022/07/07
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    category: process_creation
    product: windows
detection:
    reg:
        CommandLine|contains|all:
            - 'reg '
            - 'add'
    powershell:
        CommandLine|contains:
            - 'powershell'
            - 'set-itemproperty'
            - ' sp '
            - 'new-itemproperty'
    select_data:
        IntegrityLevel: 'Medium'
        CommandLine|contains|all:
            - 'ControlSet'
            - 'Services'
        CommandLine|contains:
            - 'ImagePath'
            - 'FailureCommand'
            - 'ServiceDLL'
    condition: (reg or powershell) and select_data
fields:
    - EventID
    - IntegrityLevel
    - CommandLine
falsepositives:
    - Unknown
level: high

```