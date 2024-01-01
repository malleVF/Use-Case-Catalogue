---
title: "DLL Load By System Process From Suspicious Locations"
status: "experimental"
created: "2022/07/17"
last_modified: "2023/09/18"
tags: [defense_evasion, t1070, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## DLL Load By System Process From Suspicious Locations

### Description

Detects when a system process (i.e. located in system32, syswow64, etc.) loads a DLL from a suspicious location or a location with permissive permissions such as "C:\Users\Public"

```yml
title: DLL Load By System Process From Suspicious Locations
id: 9e9a9002-56c4-40fd-9eff-e4b09bfa5f6c
status: experimental
description: Detects when a system process (i.e. located in system32, syswow64, etc.) loads a DLL from a suspicious location or a location with permissive permissions such as "C:\Users\Public"
references:
    - https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC (Idea)
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/07/17
modified: 2023/09/18
tags:
    - attack.defense_evasion
    - attack.t1070
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Image|startswith: 'C:\Windows\'
        ImageLoaded|startswith:
            # TODO: Add more suspicious paths as you see fit in your env
            - 'C:\Users\Public\'
            - 'C:\PerfLogs\'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
