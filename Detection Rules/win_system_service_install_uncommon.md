---
title: "Uncommon Service Installation"
status: "test"
created: "2022/03/18"
last_modified: "2023/12/04"
tags: [persistence, privilege_escalation, car_2013-09-005, t1543_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "medium"
---

## Uncommon Service Installation

### Description

Detects uncommon service installation commands

```yml
title: Uncommon Service Installation
id: 26481afe-db26-4228-b264-25a29fe6efc7
related:
    - id: ca83e9f3-657a-45d0-88d6-c1ac280caf53
      type: obsoletes
    - id: 1d61f71d-59d2-479e-9562-4ff5f4ead16b
      type: derived
status: test
description: Detects uncommon service installation commands
author: Florian Roth (Nextron Systems)
date: 2022/03/18
modified: 2023/12/04
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
    suspicious_paths:
        ImagePath|contains:
            - '\\\\.\\pipe'
            - '\Users\Public\'
            - '\Windows\Temp\'
    suspicious_encoded_flag:
        ImagePath|contains: ' -e'
    suspicious_encoded_keywords:
        ImagePath|contains:
            - ' aQBlAHgA' # PowerShell encoded commands
            - ' aWV4I' # PowerShell encoded commands
            - ' IAB' # PowerShell encoded commands
            - ' JAB' # PowerShell encoded commands
            - ' PAA' # PowerShell encoded commands
            - ' SQBFAFgA' # PowerShell encoded commands
            - ' SUVYI' # PowerShell encoded commands
    filter_optional_thor_remote:
        ImagePath|startswith: ':\WINDOWS\TEMP\thor10-remote\thor64.exe'
    filter_main_defender_def_updates:
        ImagePath|contains: ':\ProgramData\Microsoft\Windows Defender\Definition Updates\'
    condition: selection and ( suspicious_paths or all of suspicious_encoded_* ) and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium

```
