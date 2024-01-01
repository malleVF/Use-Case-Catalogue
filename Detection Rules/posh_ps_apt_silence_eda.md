---
title: "Silence.EDA Detection"
status: "test"
created: "2019/11/01"
last_modified: "2023/04/03"
tags: [execution, t1059_001, command_and_control, t1071_004, t1572, impact, t1529, g0091, s0363, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "critical"
---

## Silence.EDA Detection

### Description

Detects Silence EmpireDNSAgent as described in the Group-IP report

```yml
title: Silence.EDA Detection
id: 3ceb2083-a27f-449a-be33-14ec1b7cc973
status: test
description: Detects Silence EmpireDNSAgent as described in the Group-IP report
references:
    - https://www.group-ib.com/resources/threat-research/silence_2.0.going_global.pdf
author: Alina Stepchenkova, Group-IB, oscd.community
date: 2019/11/01
modified: 2023/04/03
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command_and_control
    - attack.t1071.004
    - attack.t1572
    - attack.impact
    - attack.t1529
    - attack.g0091
    - attack.s0363
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    empire:
        # better to randomise the order
        ScriptBlockText|contains|all:
            - 'System.Diagnostics.Process'
            - 'Stop-Computer'
            - 'Restart-Computer'
            - 'Exception in execution'
            - '$cmdargs'
            - 'Close-Dnscat2Tunnel'
    dnscat:
        # better to randomise the order
        ScriptBlockText|contains|all:
            - 'set type=$LookupType`nserver'
            - '$Command | nslookup 2>&1 | Out-String'
            - 'New-RandomDNSField'
            - '[Convert]::ToString($SYNOptions, 16)'
            - '$Session.Dead = $True'
            - '$Session["Driver"] -eq'
    condition: empire and dnscat
falsepositives:
    - Unknown
level: critical

```