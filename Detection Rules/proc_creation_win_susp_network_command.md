---
title: "Suspicious Network Command"
status: "test"
created: "2021/12/07"
last_modified: "2022/04/11"
tags: [discovery, t1016, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Suspicious Network Command

### Description

Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems

```yml
title: Suspicious Network Command
id: a29c1813-ab1f-4dde-b489-330b952e91ae
status: test
description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1016/T1016.md#atomic-test-1---system-network-configuration-discovery-on-windows
author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
date: 2021/12/07
modified: 2022/04/11
tags:
    - attack.discovery
    - attack.t1016
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'ipconfig /all'
            - 'netsh interface show interface'
            - 'arp -a'
            - 'nbtstat -n'
            - 'net config'
            - 'route print'
    condition: selection
falsepositives:
    - Administrator, hotline ask to user
level: low

```