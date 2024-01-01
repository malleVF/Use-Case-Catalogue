---
title: "Disable of ETW Trace - Powershell"
status: "test"
created: "2022/06/28"
last_modified: "2022/11/25"
tags: [defense_evasion, t1070, t1562_006, car_2016-04-002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Disable of ETW Trace - Powershell

### Description

Detects usage of powershell cmdlets to disable or remove ETW trace sessions

```yml
title: Disable of ETW Trace - Powershell
id: 115fdba9-f017-42e6-84cf-d5573bf2ddf8
related:
    - id: a238b5d0-ce2d-4414-a676-7a531b3d13d6
      type: derived
status: test
description: Detects usage of powershell cmdlets to disable or remove ETW trace sessions
references:
    - https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/28
modified: 2022/11/25
tags:
    - attack.defense_evasion
    - attack.t1070
    - attack.t1562.006
    - car.2016-04-002
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_pwsh_remove:   # Autologger provider removal
        ScriptBlockText|contains: 'Remove-EtwTraceProvider '
    selection_pwsh_set:   # Provider “Enable” property modification
        ScriptBlockText|contains|all:
            - 'Set-EtwTraceProvider '
            - '0x11'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high

```