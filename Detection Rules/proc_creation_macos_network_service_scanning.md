---
title: "MacOS Network Service Scanning"
status: "test"
created: "2020/10/21"
last_modified: "2021/11/27"
tags: [discovery, t1046, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "low"
---

## MacOS Network Service Scanning

### Description

Detects enumeration of local or remote network services.

```yml
title: MacOS Network Service Scanning
id: 84bae5d4-b518-4ae0-b331-6d4afd34d00f
status: test
description: Detects enumeration of local or remote network services.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md
author: Alejandro Ortuno, oscd.community
date: 2020/10/21
modified: 2021/11/27
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: macos
detection:
    selection_1:
        Image|endswith:
            - '/nc'
            - '/netcat'
    selection_2:
        Image|endswith:
            - '/nmap'
            - '/telnet'
    filter:
        CommandLine|contains: 'l'
    condition: (selection_1 and not filter) or selection_2
falsepositives:
    - Legitimate administration activities
level: low

```
