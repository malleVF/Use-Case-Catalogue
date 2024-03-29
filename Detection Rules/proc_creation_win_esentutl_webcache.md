---
title: "Esentutl Steals Browser Information"
status: "test"
created: "2022/02/13"
last_modified: "2022/10/31"
tags: [collection, t1005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Esentutl Steals Browser Information

### Description

One way Qbot steals sensitive information is by extracting browser data from Internet Explorer and Microsoft Edge by using the built-in utility esentutl.exe

```yml
title: Esentutl Steals Browser Information
id: 6a69f62d-ce75-4b57-8dce-6351eb55b362
status: test
description: One way Qbot steals sensitive information is by extracting browser data from Internet Explorer and Microsoft Edge by using the built-in utility esentutl.exe
references:
    - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
    - https://redcanary.com/threat-detection-report/threats/qbot/
    - https://thedfirreport.com/2022/10/31/follina-exploit-leads-to-domain-compromise/
author: frack113
date: 2022/02/13
modified: 2022/10/31
tags:
    - attack.collection
    - attack.t1005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\esentutl.exe'
        - OriginalFileName: 'esentutl.exe'
    selection_flag:
        CommandLine|contains:
            - '/r'
            - '-r'
    selection_webcache:
        CommandLine|contains: '\Windows\WebCache'
    condition: all of selection*
falsepositives:
    - Legitimate use
level: medium

```
