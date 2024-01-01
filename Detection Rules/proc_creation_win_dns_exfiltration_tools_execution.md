---
title: "DNS Exfiltration and Tunneling Tools Execution"
status: "test"
created: "2019/10/24"
last_modified: "2021/11/27"
tags: [exfiltration, t1048_001, command_and_control, t1071_004, t1132_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## DNS Exfiltration and Tunneling Tools Execution

### Description

Well-known DNS Exfiltration tools execution

```yml
title: DNS Exfiltration and Tunneling Tools Execution
id: 98a96a5a-64a0-4c42-92c5-489da3866cb0
status: test
description: Well-known DNS Exfiltration tools execution
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2021/11/27
tags:
    - attack.exfiltration
    - attack.t1048.001
    - attack.command_and_control
    - attack.t1071.004
    - attack.t1132.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\iodine.exe'
        - Image|contains: '\dnscat2'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
