---
title: "Powershell Detect Virtualization Environment"
status: "test"
created: "2021/08/03"
last_modified: "2022/03/03"
tags: [defense_evasion, t1497_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Powershell Detect Virtualization Environment

### Description

Adversaries may employ various system checks to detect and avoid virtualization and analysis environments.
This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox


```yml
title: Powershell Detect Virtualization Environment
id: d93129cd-1ee0-479f-bc03-ca6f129882e3
status: test
description: |
    Adversaries may employ various system checks to detect and avoid virtualization and analysis environments.
    This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1497.001/T1497.001.md
    - https://techgenix.com/malicious-powershell-scripts-evade-detection/
author: frack113, Duc.Le-GTSC
date: 2021/08/03
modified: 2022/03/03
tags:
    - attack.defense_evasion
    - attack.t1497.001
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_action:
        ScriptBlockText|contains:
            - Get-WmiObject
            - gwmi
    selection_module:
        ScriptBlockText|contains:
            - MSAcpi_ThermalZoneTemperature
            - Win32_ComputerSystem
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```