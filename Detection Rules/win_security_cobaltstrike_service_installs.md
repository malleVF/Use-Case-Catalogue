---
title: "CobaltStrike Service Installations - Security"
status: "test"
created: "2021/05/26"
last_modified: "2022/11/27"
tags: [execution, privilege_escalation, lateral_movement, t1021_002, t1543_003, t1569_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## CobaltStrike Service Installations - Security

### Description

Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement

```yml
title: CobaltStrike Service Installations - Security
id: d7a95147-145f-4678-b85d-d1ff4a3bb3f6
related:
    - id: 5a105d34-05fc-401e-8553-272b45c1522d
      type: derived
status: test
description: Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement
references:
    - https://www.sans.org/webcasts/119395
    - https://www.crowdstrike.com/blog/getting-the-bacon-from-cobalt-strike-beacon/
    - https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
author: Florian Roth (Nextron Systems), Wojciech Lesicki
date: 2021/05/26
modified: 2022/11/27
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.lateral_movement
    - attack.t1021.002
    - attack.t1543.003
    - attack.t1569.002
logsource:
    product: windows
    service: security
    definition: The 'System Security Extension' audit subcategory need to be enabled to log the EID 4697
detection:
    event_id:
        EventID: 4697
    selection1:
        ServiceFileName|contains|all:
            - 'ADMIN$'
            - '.exe'
    selection2:
        ServiceFileName|contains|all:
            - '%COMSPEC%'
            - 'start'
            - 'powershell'
    selection3:
        ServiceFileName|contains: 'powershell -nop -w hidden -encodedcommand'
    selection4:
        ServiceFileName|base64offset|contains: "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:"
    condition: event_id and 1 of selection*
falsepositives:
    - Unknown
level: high

```
