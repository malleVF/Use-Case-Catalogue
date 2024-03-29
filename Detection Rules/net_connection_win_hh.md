---
title: "HH.EXE Network Connections"
status: "test"
created: "2022/10/05"
last_modified: ""
tags: [defense_evasion, t1218_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## HH.EXE Network Connections

### Description

Detects network connections made by the "hh.exe" process, which could indicate the execution/download of remotely hosted .chm files

```yml
title: HH.EXE Network Connections
id: 468a8cea-2920-4909-a593-0cbe1d96674a
related:
    - id: f57c58b3-ee69-4ef5-9041-455bf39aaa89
      type: derived
status: test
description: Detects network connections made by the "hh.exe" process, which could indicate the execution/download of remotely hosted .chm files
references:
    - https://www.splunk.com/en_us/blog/security/follina-for-protocol-handlers.html
    - https://github.com/redcanaryco/atomic-red-team/blob/1cf4dd51f83dcb0ebe6ade902d6157ad2dbc6ac8/atomics/T1218.001/T1218.001.md
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/10/05
tags:
    - attack.defense_evasion
    - attack.t1218.001
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\hh.exe'
        Initiated: 'true'
        DestinationPort:
            - 80
            - 443
            - 135
            - 445
    condition: selection
falsepositives:
    - Unknown
level: medium

```
