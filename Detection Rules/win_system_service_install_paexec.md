---
title: "PAExec Service Installation"
status: "test"
created: "2022/10/26"
last_modified: ""
tags: [execution, t1569_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "medium"
---

## PAExec Service Installation

### Description

Detects PAExec service installation

```yml
title: PAExec Service Installation
id: de7ce410-b3fb-4e8a-b38c-3b999e2c3420
status: test
description: Detects PAExec service installation
references:
    - https://www.poweradmin.com/paexec/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/10/26
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection_eid:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_image:
        - ServiceName|startswith: 'PAExec-'
        - ImagePath|startswith: 'C:\WINDOWS\PAExec-'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
