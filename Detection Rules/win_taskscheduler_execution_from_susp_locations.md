---
title: "Scheduled Task Executed From A Suspicious Location"
status: "experimental"
created: "2022/12/05"
last_modified: "2023/02/07"
tags: [persistence, t1053_005, detection_rule]
logsrc_product: "windows"
logsrc_service: "taskscheduler"
level: "medium"
---

## Scheduled Task Executed From A Suspicious Location

### Description

Detects the execution of Scheduled Tasks where the Program being run is located in a suspicious location or it's an unusale program to be run from a Scheduled Task

```yml
title: Scheduled Task Executed From A Suspicious Location
id: 424273ea-7cf8-43a6-b712-375f925e481f
status: experimental
description: Detects the execution of Scheduled Tasks where the Program being run is located in a suspicious location or it's an unusale program to be run from a Scheduled Task
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/12/05
modified: 2023/02/07
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    product: windows
    service: taskscheduler
    definition: 'Requirements: The "Microsoft-Windows-TaskScheduler/Operational" is disabled by default and needs to be enabled in order for this detection to trigger'
detection:
    selection:
        EventID: 129 # Created Task Process
        Path|contains:
            - 'C:\Windows\Temp\'
            - '\AppData\Local\Temp\'
            - '\Desktop\'
            - '\Downloads\'
            - '\Users\Public\'
            - 'C:\Temp\'
    # If you experience FP. Uncomment the filter below and add the specific TaskName with the Program to it
    # filter:
    #     TaskName: '\Exact\Task\Name'
    #     Path: 'Exact\Path'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
