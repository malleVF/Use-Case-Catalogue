---
title: "PowerShell Scripts Installed as Services - Security"
status: "test"
created: "2020/10/06"
last_modified: "2022/11/29"
tags: [execution, t1569_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## PowerShell Scripts Installed as Services - Security

### Description

Detects powershell script installed as a Service

```yml
title: PowerShell Scripts Installed as Services - Security
id: 2a926e6a-4b81-4011-8a96-e36cc8c04302
related:
    - id: a2e5019d-a658-4c6a-92bf-7197b54e2cae
      type: derived
status: test
description: Detects powershell script installed as a Service
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
author: oscd.community, Natalia Shornikova
date: 2020/10/06
modified: 2022/11/29
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    product: windows
    service: security
    definition: The 'System Security Extension' audit subcategory need to be enabled to log the EID 4697
detection:
    selection:
        EventID: 4697
        ServiceFileName|contains:
            - 'powershell'
            - 'pwsh'
    condition: selection
falsepositives:
    - Unknown
level: high

```