---
title: "Hardware Model Reconnaissance Via Wmic.EXE"
status: "experimental"
created: "2023/02/14"
last_modified: ""
tags: [execution, t1047, car_2016-03-002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Hardware Model Reconnaissance Via Wmic.EXE

### Description

Detects the execution of WMIC with the "csproduct" which is used to obtain information such as hardware models and vendor information

```yml
title: Hardware Model Reconnaissance Via Wmic.EXE
id: 3e3ceccd-6c06-48b8-b5ff-ab1d25db8c1d
status: experimental
description: Detects the execution of WMIC with the "csproduct" which is used to obtain information such as hardware models and vendor information
references:
    - https://jonconwayuk.wordpress.com/2014/01/31/wmic-csproduct-using-wmi-to-identify-make-and-model-of-hardware/
    - https://www.uptycs.com/blog/kuraystealer-a-bandit-using-discord-webhooks
author: Florian Roth (Nextron Systems)
date: 2023/02/14
tags:
    - attack.execution
    - attack.t1047
    - car.2016-03-002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\wmic.exe'
        - OriginalFileName: 'wmic.exe'
    selection_cli:
        CommandLine|contains: 'csproduct'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
