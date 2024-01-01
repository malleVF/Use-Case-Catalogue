---
title: "ImagingDevices Unusual Parent/Child Processes"
status: "test"
created: "2022/09/27"
last_modified: "2022/12/29"
tags: [defense_evasion, execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## ImagingDevices Unusual Parent/Child Processes

### Description

Detects unusual parent or children of the ImagingDevices.exe (Windows Contacts) process as seen being used with Bumblebee activity

```yml
title: ImagingDevices Unusual Parent/Child Processes
id: f11f2808-adb4-46c0-802a-8660db50fa99
status: test
description: Detects unusual parent or children of the ImagingDevices.exe (Windows Contacts) process as seen being used with Bumblebee activity
references:
    - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/27
modified: 2022/12/29
tags:
    - attack.defense_evasion
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            # Add more if known
            - \WmiPrvSE.exe
            - \svchost.exe
            - \dllhost.exe
        Image|endswith: '\ImagingDevices.exe'
    selection_child:
        # You can add specific suspicious child processes (such as cmd, powershell...) to increase the accuracy
        ParentImage|endswith: '\ImagingDevices.exe'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high

```