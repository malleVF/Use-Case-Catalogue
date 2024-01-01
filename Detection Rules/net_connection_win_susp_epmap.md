---
title: "Suspicious Epmap Connection"
status: "experimental"
created: "2022/07/14"
last_modified: "2023/09/28"
tags: [lateral_movement, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Epmap Connection

### Description

Detects suspicious "epmap" connection to a remote computer via remote procedure call (RPC)

```yml
title: Suspicious Epmap Connection
id: 628d7a0b-7b84-4466-8552-e6138bc03b43
status: experimental
description: Detects suspicious "epmap" connection to a remote computer via remote procedure call (RPC)
references:
    - https://github.com/RiccardoAncarani/TaskShell/
author: frack113, Tim Shelton (fps)
date: 2022/07/14
modified: 2023/09/28
tags:
    - attack.lateral_movement
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Protocol: tcp
        Initiated: 'true'
        DestinationPort: 135
        # DestinationPortName: epmap
    filter_image:
        Image|startswith:
            - C:\Windows\
            - C:\ProgramData\Amazon\SSM\Update\amazon-ssm-agent-updater
    filter_image_null1:
        Image: null
    filter_image_null2:
        Image: ''
    filter_image_unknown:
        Image: '<unknown process>'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high

```
