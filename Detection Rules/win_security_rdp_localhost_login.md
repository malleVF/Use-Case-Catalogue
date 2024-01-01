---
title: "RDP Login from Localhost"
status: "test"
created: "2019/01/28"
last_modified: "2022/10/09"
tags: [lateral_movement, car_2013-07-002, t1021_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## RDP Login from Localhost

### Description

RDP login with localhost source address may be a tunnelled login

```yml
title: RDP Login from Localhost
id: 51e33403-2a37-4d66-a574-1fda1782cc31
status: test
description: RDP login with localhost source address may be a tunnelled login
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
author: Thomas Patzke
date: 2019/01/28
modified: 2022/10/09
tags:
    - attack.lateral_movement
    - car.2013-07-002
    - attack.t1021.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
        IpAddress:
            - '::1'
            - '127.0.0.1'
    condition: selection
falsepositives:
    - Unknown
level: high

```
