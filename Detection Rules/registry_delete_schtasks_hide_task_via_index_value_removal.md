---
title: "Removal Of Index Value to Hide Schedule Task - Registry"
status: "experimental"
created: "2022/08/26"
last_modified: "2023/02/08"
tags: [defense_evasion, t1562, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Removal Of Index Value to Hide Schedule Task - Registry

### Description

Detects when the "index" value of a scheduled task is removed or deleted from the registry. Which effectively hides it from any tooling such as "schtasks /query"

```yml
title: Removal Of Index Value to Hide Schedule Task - Registry
id: 526cc8bc-1cdc-48ad-8b26-f19bff969cec
related:
    - id: acd74772-5f88-45c7-956b-6a7b36c294d2
      type: similar
    - id: 5b16df71-8615-4f7f-ac9b-6c43c0509e61
      type: similar
status: experimental
description: Detects when the "index" value of a scheduled task is removed or deleted from the registry. Which effectively hides it from any tooling such as "schtasks /query"
references:
    - https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/26
modified: 2023/02/08
tags:
    - attack.defense_evasion
    - attack.t1562
logsource:
    product: windows
    category: registry_delete
detection:
    selection:
        EventType: DeleteKey
        TargetObject|contains|all:
            - '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\'
            - 'Index'
    condition: selection
falsepositives:
    - Unknown
level: medium

```