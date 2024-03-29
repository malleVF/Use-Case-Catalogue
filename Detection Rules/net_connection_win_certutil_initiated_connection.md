---
title: "Connection Initiated Via Certutil.EXE"
status: "test"
created: "2022/09/02"
last_modified: "2022/10/04"
tags: [command_and_control, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Connection Initiated Via Certutil.EXE

### Description

Detects a network connection initiated by the certutil.exe tool.
Attackers can abuse the utility in order to download malware or additional payloads.


```yml
title: Connection Initiated Via Certutil.EXE
id: 0dba975d-a193-4ed1-a067-424df57570d1
status: test
description: |
    Detects a network connection initiated by the certutil.exe tool.
    Attackers can abuse the utility in order to download malware or additional payloads.
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
author: frack113, Florian Roth (Nextron Systems)
date: 2022/09/02
modified: 2022/10/04
tags:
    - attack.command_and_control
    - attack.t1105
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
        Initiated: 'true'
        DestinationPort:
            - 80
            - 135
            - 443
            - 445
    condition: selection
falsepositives:
    - Unknown
level: high

```
