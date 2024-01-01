---
title: "Cisco Discovery"
status: "test"
created: "2019/08/12"
last_modified: "2023/01/04"
tags: [discovery, t1083, t1201, t1057, t1018, t1082, t1016, t1049, t1033, t1124, detection_rule]
logsrc_product: "cisco"
logsrc_service: "aaa"
level: "low"
---

## Cisco Discovery

### Description

Find information about network devices that is not stored in config files

```yml
title: Cisco Discovery
id: 9705a6a1-6db6-4a16-a987-15b7151e299b
status: test
description: Find information about network devices that is not stored in config files
author: Austin Clark
date: 2019/08/12
modified: 2023/01/04
tags:
    - attack.discovery
    - attack.t1083
    - attack.t1201
    - attack.t1057
    - attack.t1018
    - attack.t1082
    - attack.t1016
    - attack.t1049
    - attack.t1033
    - attack.t1124
logsource:
    product: cisco
    service: aaa
detection:
    keywords:
        - 'dir'
        - 'show processes'
        - 'show arp'
        - 'show cdp'
        - 'show version'
        - 'show ip route'
        - 'show ip interface'
        - 'show ip sockets'
        - 'show users'
        - 'show ssh'
        - 'show clock'
    condition: keywords
fields:
    - src
    - CmdSet
    - User
    - Privilege_Level
    - Remote_Address
falsepositives:
    - Commonly used by administrators for troubleshooting
level: low

```
