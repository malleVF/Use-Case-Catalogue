---
title: "Disable Security Events Logging Adding Reg Key MiniNt"
status: "test"
created: "2019/10/25"
last_modified: "2021/11/27"
tags: [defense_evasion, t1562_001, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Disable Security Events Logging Adding Reg Key MiniNt

### Description

Detects the addition of a key 'MiniNt' to the registry. Upon a reboot, Windows Event Log service will stopped write events.

```yml
title: Disable Security Events Logging Adding Reg Key MiniNt
id: 919f2ef0-be2d-4a7a-b635-eb2b41fde044
status: test
description: Detects the addition of a key 'MiniNt' to the registry. Upon a reboot, Windows Event Log service will stopped write events.
references:
    - https://twitter.com/0gtweet/status/1182516740955226112
author: Ilyas Ochkov, oscd.community
date: 2019/10/25
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1112
logsource:
    category: registry_event
    product: windows
detection:
    selection:
    # Sysmon gives us HKLM\SYSTEM\CurrentControlSet\.. if ControlSetXX is the selected one
        - TargetObject: 'HKLM\SYSTEM\CurrentControlSet\Control\MiniNt'
          EventType: 'CreateKey'    # we don't want deletekey
    # key rename
        - NewName: 'HKLM\SYSTEM\CurrentControlSet\Control\MiniNt'
    condition: selection
fields:
    - EventID
    - Image
    - TargetObject
    - NewName
falsepositives:
    - Unknown
level: high

```