---
title: "Atbroker Registry Change"
status: "test"
created: "2020/10/13"
last_modified: "2023/01/19"
tags: [defense_evasion, t1218, persistence, t1547, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Atbroker Registry Change

### Description

Detects creation/modification of Assistive Technology applications and persistence with usage of 'at'

```yml
title: Atbroker Registry Change
id: 9577edbb-851f-4243-8c91-1d5b50c1a39b
status: test
description: Detects creation/modification of Assistive Technology applications and persistence with usage of 'at'
references:
    - http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
    - https://lolbas-project.github.io/lolbas/Binaries/Atbroker/
author: Mateusz Wydra, oscd.community
date: 2020/10/13
modified: 2023/01/19
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.persistence
    - attack.t1547
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains:
            - 'Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs'
            - 'Software\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration'
    filter_atbroker:
        Image: 'C:\Windows\system32\atbroker.exe'
        TargetObject|contains: '\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration'
        Details: '(Empty)'
    filter_uninstallers:
        Image|startswith: 'C:\Windows\Installer\MSI'
        TargetObject|contains: 'Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs'
    condition: selection and not 1 of filter_*
falsepositives:
    - Creation of non-default, legitimate at usage
level: medium

```
