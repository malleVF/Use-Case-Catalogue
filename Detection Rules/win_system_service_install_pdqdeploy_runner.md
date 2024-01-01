---
title: "New PDQDeploy Service - Client Side"
status: "test"
created: "2022/07/22"
last_modified: ""
tags: [privilege_escalation, t1543_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "medium"
---

## New PDQDeploy Service - Client Side

### Description

Detects PDQDeploy service installation on the target system.
When a package is deployed via PDQDeploy it installs a remote service on the target machine with the name "PDQDeployRunner-X" where "X" is an integer starting from 1


```yml
title: New PDQDeploy Service - Client Side
id: b98a10af-1e1e-44a7-bab2-4cc026917648
status: test
description: |
    Detects PDQDeploy service installation on the target system.
    When a package is deployed via PDQDeploy it installs a remote service on the target machine with the name "PDQDeployRunner-X" where "X" is an integer starting from 1
references:
    - https://documentation.pdq.com/PDQDeploy/13.0.3.0/index.html?windows-services.htm
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/07/22
tags:
    - attack.privilege_escalation
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection_root:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_service:
        - ImagePath|contains: 'PDQDeployRunner-'
        - ServiceName|startswith: 'PDQDeployRunner-'
    condition: all of selection_*
falsepositives:
    - Legitimate use of the tool
level: medium

```
