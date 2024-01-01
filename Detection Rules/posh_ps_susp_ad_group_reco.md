---
title: "AD Groups Or Users Enumeration Using PowerShell - ScriptBlock"
status: "test"
created: "2021/12/15"
last_modified: "2022/12/25"
tags: [discovery, t1069_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## AD Groups Or Users Enumeration Using PowerShell - ScriptBlock

### Description

Adversaries may attempt to find domain-level groups and permission settings.
The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group.
Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.


```yml
title: AD Groups Or Users Enumeration Using PowerShell - ScriptBlock
id: 88f0884b-331d-403d-a3a1-b668cf035603
status: test
description: |
    Adversaries may attempt to find domain-level groups and permission settings.
    The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group.
    Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1069.002/T1069.002.md
author: frack113
date: 2021/12/15
modified: 2022/12/25
tags:
    - attack.discovery
    - attack.t1069.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    test_2:
        ScriptBlockText|contains: get-ADPrincipalGroupMembership
    test_7:
        ScriptBlockText|contains|all:
            - get-aduser
            - '-f '
            - '-pr '
            - DoesNotRequirePreAuth
    condition: 1 of test_*
falsepositives:
    - Unknown
level: low

```