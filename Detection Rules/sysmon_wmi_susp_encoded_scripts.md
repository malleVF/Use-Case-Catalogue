---
title: "Suspicious Encoded Scripts in a WMI Consumer"
status: "test"
created: "2021/09/01"
last_modified: "2022/10/09"
tags: [execution, t1047, persistence, t1546_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Encoded Scripts in a WMI Consumer

### Description

Detects suspicious encoded payloads in WMI Event Consumers

```yml
title: Suspicious Encoded Scripts in a WMI Consumer
id: 83844185-1c5b-45bc-bcf3-b5bf3084ca5b
status: test
description: Detects suspicious encoded payloads in WMI Event Consumers
references:
    - https://github.com/RiccardoAncarani/LiquidSnake
author: Florian Roth (Nextron Systems)
date: 2021/09/01
modified: 2022/10/09
tags:
    - attack.execution
    - attack.t1047
    - attack.persistence
    - attack.t1546.003
logsource:
    product: windows
    category: wmi_event
detection:
    selection_destination:
        Destination|base64offset|contains:
            - 'WriteProcessMemory'
            - 'This program cannot be run in DOS mode'
            - 'This program must be run under Win32'
    condition: selection_destination
fields:
    - User
    - Operation
falsepositives:
    - Unknown
level: high

```
