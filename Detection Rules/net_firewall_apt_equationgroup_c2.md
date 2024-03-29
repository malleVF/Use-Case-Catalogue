---
title: "Equation Group C2 Communication"
status: "test"
created: "2017/04/15"
last_modified: "2021/11/27"
tags: [command_and_control, g0020, t1041, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Equation Group C2 Communication

### Description

Detects communication to C2 servers mentioned in the operational notes of the ShadowBroker leak of EquationGroup C2 tools

```yml
title: Equation Group C2 Communication
id: 881834a4-6659-4773-821e-1c151789d873
status: test
description: Detects communication to C2 servers mentioned in the operational notes of the ShadowBroker leak of EquationGroup C2 tools
references:
    - https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation
    - https://medium.com/@msuiche/the-nsa-compromised-swift-network-50ec3000b195
author: Florian Roth (Nextron Systems)
date: 2017/04/15
modified: 2021/11/27
tags:
    - attack.command_and_control
    - attack.g0020
    - attack.t1041
logsource:
    category: firewall
detection:
    select_outgoing:
        dst_ip:
            - '69.42.98.86'
            - '89.185.234.145'
    select_incoming:
        src_ip:
            - '69.42.98.86'
            - '89.185.234.145'
    condition: 1 of select*
falsepositives:
    - Unknown
level: high

```
