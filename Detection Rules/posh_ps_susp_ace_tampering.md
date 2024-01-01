---
title: "Potential Persistence Via Security Descriptors - ScriptBlock"
status: "test"
created: "2023/01/05"
last_modified: ""
tags: [persistence, defense_evasion, privilege_escalation, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Persistence Via Security Descriptors - ScriptBlock

### Description

Detects usage of certain functions and keywords that are used to manipulate security descriptors in order to potentially set a backdoor. As seen used in the DAMP project.

```yml
title: Potential Persistence Via Security Descriptors - ScriptBlock
id: 2f77047c-e6e9-4c11-b088-a3de399524cd
status: test
description: Detects usage of certain functions and keywords that are used to manipulate security descriptors in order to potentially set a backdoor. As seen used in the DAMP project.
references:
    - https://github.com/HarmJ0y/DAMP
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/01/05
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.privilege_escalation
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'win32_Trustee'
            - 'win32_Ace'
            - '.AccessMask'
            - '.AceType'
            - '.SetSecurityDescriptor'
        ScriptBlockText|contains:
            - '\Lsa\JD'
            - '\Lsa\Skew1'
            - '\Lsa\Data'
            - '\Lsa\GBG'
    condition: selection
falsepositives:
    - Unknown
level: high

```
