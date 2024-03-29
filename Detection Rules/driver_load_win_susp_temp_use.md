---
title: "Driver Load From A Temporary Directory"
status: "test"
created: "2017/02/12"
last_modified: "2021/11/27"
tags: [persistence, privilege_escalation, t1543_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Driver Load From A Temporary Directory

### Description

Detects a driver load from a temporary directory

```yml
title: Driver Load From A Temporary Directory
id: 2c4523d5-d481-4ed0-8ec3-7fbf0cb41a75
status: test
description: Detects a driver load from a temporary directory
author: Florian Roth (Nextron Systems)
date: 2017/02/12
modified: 2021/11/27
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1543.003
logsource:
    category: driver_load
    product: windows
detection:
    selection:
        ImageLoaded|contains: '\Temp\'
    condition: selection
falsepositives:
    - There is a relevant set of false positives depending on applications in the environment
level: high

```
