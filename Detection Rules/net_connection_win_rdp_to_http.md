---
title: "RDP to HTTP or HTTPS Target Ports"
status: "test"
created: "2022/04/29"
last_modified: "2022/07/14"
tags: [command_and_control, t1572, lateral_movement, t1021_001, car_2013-07-002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## RDP to HTTP or HTTPS Target Ports

### Description

Detects svchost hosting RDP termsvcs communicating to target systems on TCP port 80 or 443

```yml
title: RDP to HTTP or HTTPS Target Ports
id: b1e5da3b-ca8e-4adf-915c-9921f3d85481
status: test
description: Detects svchost hosting RDP termsvcs communicating to target systems on TCP port 80 or 443
references:
    - https://twitter.com/tekdefense/status/1519711183162556416?s=12&t=OTsHCBkQOTNs1k3USz65Zg
    - https://www.mandiant.com/resources/bypassing-network-restrictions-through-rdp-tunneling
author: Florian Roth (Nextron Systems)
date: 2022/04/29
modified: 2022/07/14
tags:
    - attack.command_and_control
    - attack.t1572
    - attack.lateral_movement
    - attack.t1021.001
    - car.2013-07-002
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
        Initiated: 'true'
        SourcePort: 3389
        DestinationPort:
            - 80
            - 443
    condition: selection
falsepositives:
    - Unknown
level: high

```
