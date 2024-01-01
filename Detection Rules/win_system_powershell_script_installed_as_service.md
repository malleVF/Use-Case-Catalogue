---
title: "PowerShell Scripts Installed as Services"
status: "test"
created: "2020/10/06"
last_modified: "2022/12/25"
tags: [execution, t1569_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "high"
---

## PowerShell Scripts Installed as Services

### Description

Detects powershell script installed as a Service

```yml
title: PowerShell Scripts Installed as Services
id: a2e5019d-a658-4c6a-92bf-7197b54e2cae
status: test
description: Detects powershell script installed as a Service
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
author: oscd.community, Natalia Shornikova
date: 2020/10/06
modified: 2022/12/25
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains:
            - 'powershell'
            - 'pwsh'
    condition: selection
falsepositives:
    - Unknown
level: high

```
