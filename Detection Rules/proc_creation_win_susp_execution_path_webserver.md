---
title: "Execution in Webserver Root Folder"
status: "test"
created: "2019/01/16"
last_modified: "2021/11/27"
tags: [persistence, t1505_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Execution in Webserver Root Folder

### Description

Detects a suspicious program execution in a web service root folder (filter out false positives)

```yml
title: Execution in Webserver Root Folder
id: 35efb964-e6a5-47ad-bbcd-19661854018d
status: test
description: Detects a suspicious program execution in a web service root folder (filter out false positives)
author: Florian Roth (Nextron Systems)
date: 2019/01/16
modified: 2021/11/27
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '\wwwroot\'
            - '\wmpub\'
            - '\htdocs\'
    filter:
        Image|contains:
            - 'bin\'
            - '\Tools\'
            - '\SMSComponent\'
        ParentImage|endswith: '\services.exe'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Various applications
    - Tools that include ping or nslookup command invocations
level: medium

```
