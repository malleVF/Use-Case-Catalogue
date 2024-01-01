---
title: "Potential Remote Desktop Tunneling"
status: "test"
created: "2022/09/27"
last_modified: ""
tags: [lateral_movement, t1021, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Remote Desktop Tunneling

### Description

Detects potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended destination.

```yml
title: Potential Remote Desktop Tunneling
id: 8a3038e8-9c9d-46f8-b184-66234a160f6f
status: test
description: Detects potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended destination.
references:
    - https://www.elastic.co/guide/en/security/current/potential-remote-desktop-tunneling-detected.html
author: Tim Rauch
date: 2022/09/27
tags:
    - attack.lateral_movement
    - attack.t1021
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: ':3389' # RDP port and usual SSH tunneling related switches in command line
    selection_opt:
        CommandLine|contains:
            - ' -L '
            - ' -P '
            - ' -R '
            - ' -pw '
            - ' -ssh '
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```
