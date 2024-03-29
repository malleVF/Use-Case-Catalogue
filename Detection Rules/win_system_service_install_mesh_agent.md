---
title: "Mesh Agent Service Installation"
status: "test"
created: "2022/11/28"
last_modified: ""
tags: [command_and_control, t1219, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "medium"
---

## Mesh Agent Service Installation

### Description

Detects a Mesh Agent service installation. Mesh Agent is used to remotely manage computers

```yml
title: Mesh Agent Service Installation
id: e0d1ad53-c7eb-48ec-a87a-72393cc6cedc
status: test
description: Detects a Mesh Agent service installation. Mesh Agent is used to remotely manage computers
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
        - ImagePath|contains: 'MeshAgent.exe'
        - ServiceName|contains: 'Mesh Agent'
    condition: all of selection_*
falsepositives:
    - Legitimate use of the tool
level: medium

```
