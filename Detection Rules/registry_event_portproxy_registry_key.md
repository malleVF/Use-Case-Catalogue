---
title: "PortProxy Registry Key"
status: "test"
created: "2021/06/22"
last_modified: "2022/10/09"
tags: [lateral_movement, defense_evasion, command_and_control, t1090, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PortProxy Registry Key

### Description

Detects the modification of PortProxy registry key which is used for port forwarding. For command execution see rule win_netsh_port_fwd.yml.

```yml
title: PortProxy Registry Key
id: a54f842a-3713-4b45-8c84-5f136fdebd3c
status: test
description: Detects the modification of PortProxy registry key which is used for port forwarding. For command execution see rule win_netsh_port_fwd.yml.
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
    - https://adepts.of0x.cc/netsh-portproxy-code/
    - https://www.dfirnotes.net/portproxy_detection/
author: Andreas Hunkeler (@Karneades)
date: 2021/06/22
modified: 2022/10/09
tags:
    - attack.lateral_movement
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1090
logsource:
    category: registry_event
    product: windows
detection:
    selection_registry:
        TargetObject: 'HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'
    condition: selection_registry
falsepositives:
    - WSL2 network bridge PowerShell script used for WSL/Kubernetes/Docker (e.g. https://github.com/microsoft/WSL/issues/4150#issuecomment-504209723)
    - Synergy Software KVM (https://symless.com/synergy)
level: medium

```
