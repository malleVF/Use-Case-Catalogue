---
title: "Service Installation with Suspicious Folder Pattern"
status: "test"
created: "2022/03/18"
last_modified: "2022/03/24"
tags: [persistence, privilege_escalation, car_2013-09-005, t1543_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "high"
---

## Service Installation with Suspicious Folder Pattern

### Description

Detects service installation with suspicious folder patterns

```yml
title: Service Installation with Suspicious Folder Pattern
id: 1b2ae822-6fe1-43ba-aa7c-d1a3b3d1d5f2
status: test
description: Detects service installation with suspicious folder patterns
author: pH-T (Nextron Systems)
date: 2022/03/18
modified: 2022/03/24
tags:
    - attack.persistence
    - attack.privilege_escalation
    - car.2013-09-005
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    suspicious1:
        - ImagePath|re: '^[Cc]:\\[Pp]rogram[Dd]ata\\.{1,9}\.exe'
        - ImagePath|re: '^[Cc]:\\.{1,9}\.exe'
    condition: selection and 1 of suspicious*
falsepositives:
    - Unknown
level: high

```