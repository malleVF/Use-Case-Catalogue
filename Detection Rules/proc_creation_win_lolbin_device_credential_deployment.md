---
title: "DeviceCredentialDeployment Execution"
status: "test"
created: "2022/08/19"
last_modified: ""
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## DeviceCredentialDeployment Execution

### Description

Detects the execution of DeviceCredentialDeployment to hide a process from view

```yml
title: DeviceCredentialDeployment Execution
id: b8b1b304-a60f-4999-9a6e-c547bde03ffd
status: test
description: Detects the execution of DeviceCredentialDeployment to hide a process from view
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/147
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/19
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\DeviceCredentialDeployment.exe'
    condition: selection
falsepositives:
    - Unlikely
level: medium

```
