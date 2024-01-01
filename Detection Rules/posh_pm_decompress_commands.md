---
title: "PowerShell Decompress Commands"
status: "test"
created: "2020/05/02"
last_modified: "2022/12/25"
tags: [defense_evasion, t1140, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "informational"
---

## PowerShell Decompress Commands

### Description

A General detection for specific decompress commands in PowerShell logs. This could be an adversary decompressing files.

```yml
title: PowerShell Decompress Commands
id: 1ddc1472-8e52-4f7d-9f11-eab14fc171f5
related:
    - id: 81fbdce6-ee49-485a-908d-1a728c5dcb09
      type: derived
status: test
description: A General detection for specific decompress commands in PowerShell logs. This could be an adversary decompressing files.
references:
    - https://github.com/OTRF/detection-hackathon-apt29/issues/8
    - https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/4.A.3_09F29912-8E93-461E-9E89-3F06F6763383.md
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020/05/02
modified: 2022/12/25
tags:
    - attack.defense_evasion
    - attack.t1140
logsource:
    product: windows
    category: ps_module
    definition: 0ad03ef1-f21b-4a79-8ce8-e6900c54b65b
detection:
    selection_4103:
        Payload|contains: 'Expand-Archive'
    condition: selection_4103
falsepositives:
    - Unknown
level: informational

```