---
title: "Suspicious Where Execution"
status: "test"
created: "2021/12/13"
last_modified: "2022/06/29"
tags: [discovery, t1217, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Suspicious Where Execution

### Description

Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
internal network resources such as servers, tools/dashboards, or other related infrastructure.


```yml
title: Suspicious Where Execution
id: 725a9768-0f5e-4cb3-aec2-bc5719c6831a
status: test
description: |
    Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
    Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
    internal network resources such as servers, tools/dashboards, or other related infrastructure.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1217/T1217.md
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2021/12/13
modified: 2022/06/29
tags:
    - attack.discovery
    - attack.t1217
logsource:
    category: process_creation
    product: windows
detection:
    where_exe:
        - Image|endswith: '\where.exe'
        - OriginalFileName: 'where.exe'
    where_opt:
        CommandLine|contains:
            # Firefox Data
            - 'places.sqlite'
            - 'cookies.sqlite'
            - 'formhistory.sqlite'
            - 'logins.json'
            - 'key4.db'
            - 'key3.db'
            - 'sessionstore.jsonlz4'
            # Chrome Data
            - 'History'
            - 'Bookmarks'
            - 'Cookies'
            - 'Login Data'
    condition: all of where_*
falsepositives:
    - Unknown
level: low

```