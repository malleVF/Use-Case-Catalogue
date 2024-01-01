---
title: "Potential Privilege Escalation via Service Permissions Weakness"
status: "test"
created: "2019/10/26"
last_modified: "2023/01/30"
tags: [privilege_escalation, t1574_011, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Privilege Escalation via Service Permissions Weakness

### Description

Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level

```yml
title: Potential Privilege Escalation via Service Permissions Weakness
id: 0f9c21f1-6a73-4b0e-9809-cb562cb8d981
status: test
description: Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://pentestlab.blog/2017/03/31/insecure-registry-permissions/
author: Teymur Kheirkhabarov
date: 2019/10/26
modified: 2023/01/30
tags:
    - attack.privilege_escalation
    - attack.t1574.011
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        IntegrityLevel: 'Medium'
        CommandLine|contains|all:
            - 'ControlSet'
            - 'services'
        CommandLine|contains:
            - '\ImagePath'
            - '\FailureCommand'
            - '\ServiceDll'
    condition: selection
falsepositives:
    - Unknown
level: high

```