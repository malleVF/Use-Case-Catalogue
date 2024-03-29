---
title: "TacticalRMM Service Installation"
status: "test"
created: "2022/11/28"
last_modified: ""
tags: [command_and_control, t1219, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "medium"
---

## TacticalRMM Service Installation

### Description

Detects a TacticalRMM service installation. Tactical RMM is a remote monitoring & management tool.

```yml
title: TacticalRMM Service Installation
id: 4bb79b62-ef12-4861-981d-2aab43fab642
status: test
description: Detects a TacticalRMM service installation. Tactical RMM is a remote monitoring & management tool.
references:
    - https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/11/28
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    product: windows
    service: system
detection:
    selection_root:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_service:
        - ImagePath|contains: 'tacticalrmm.exe'
        - ServiceName|contains: 'TacticalRMM Agent Service'
    condition: all of selection_*
falsepositives:
    - Legitimate use of the tool
level: medium

```
