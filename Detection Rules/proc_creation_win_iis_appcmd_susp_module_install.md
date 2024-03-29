---
title: "IIS Native-Code Module Command Line Installation"
status: "test"
created: "2019/12/11"
last_modified: "2023/01/22"
tags: [persistence, t1505_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## IIS Native-Code Module Command Line Installation

### Description

Detects suspicious IIS native-code module installations via command line

```yml
title: IIS Native-Code Module Command Line Installation
id: 9465ddf4-f9e4-4ebd-8d98-702df3a93239
status: test
description: Detects suspicious IIS native-code module installations via command line
references:
    - https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
    - https://www.microsoft.com/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/
author: Florian Roth (Nextron Systems)
date: 2019/12/11
modified: 2023/01/22
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\appcmd.exe'
        - OriginalFileName: 'appcmd.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'install'
            - 'module'
        CommandLine|contains:
            - '/name:'
            - '-name:'
    filter_iis_setup:
        ParentImage: 'C:\Windows\System32\inetsrv\iissetup.exe'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Unknown as it may vary from organisation to organisation how admins use to install IIS modules
level: medium

```
