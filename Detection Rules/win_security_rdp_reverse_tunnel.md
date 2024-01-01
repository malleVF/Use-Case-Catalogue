---
title: "RDP over Reverse SSH Tunnel WFP"
status: "test"
created: "2019/02/16"
last_modified: "2022/09/02"
tags: [defense_evasion, command_and_control, lateral_movement, t1090_001, t1090_002, t1021_001, car_2013-07-002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## RDP over Reverse SSH Tunnel WFP

### Description

Detects svchost hosting RDP termsvcs communicating with the loopback address

```yml
title: RDP over Reverse SSH Tunnel WFP
id: 5bed80b6-b3e8-428e-a3ae-d3c757589e41
status: test
description: Detects svchost hosting RDP termsvcs communicating with the loopback address
references:
    - https://twitter.com/SBousseaden/status/1096148422984384514
    - https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/44fbe85f72ee91582876b49678f9a26292a155fb/Command%20and%20Control/DE_RDP_Tunnel_5156.evtx
author: Samir Bousseaden
date: 2019/02/16
modified: 2022/09/02
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.lateral_movement
    - attack.t1090.001
    - attack.t1090.002
    - attack.t1021.001
    - car.2013-07-002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5156
    sourceRDP:
        SourcePort: 3389
        DestAddress:
            - '127.*'
            - '::1'
    destinationRDP:
        DestPort: 3389
        SourceAddress:
            - '127.*'
            - '::1'
    filter_app_container:
        FilterOrigin: 'AppContainer Loopback'
    filter_thor:  # checking BlueKeep vulnerability
        Application|endswith:
            - '\thor.exe'
            - '\thor64.exe'
    condition: selection and ( sourceRDP or destinationRDP ) and not 1 of filter*
falsepositives:
    - Programs that connect locally to the RDP port
level: high

```
