---
title: "Remote Task Creation via ATSVC Named Pipe - Zeek"
status: "test"
created: "2020/04/03"
last_modified: "2022/12/27"
tags: [lateral_movement, persistence, car_2013-05-004, car_2015-04-001, t1053_002, detection_rule]
logsrc_product: "zeek"
logsrc_service: "smb_files"
level: "medium"
---

## Remote Task Creation via ATSVC Named Pipe - Zeek

### Description

Detects remote task creation via at.exe or API interacting with ATSVC namedpipe

```yml
title: Remote Task Creation via ATSVC Named Pipe - Zeek
id: dde85b37-40cd-4a94-b00c-0b8794f956b5
related:
    - id: f6de6525-4509-495a-8a82-1f8b0ed73a00
      type: derived
status: test
description: Detects remote task creation via at.exe or API interacting with ATSVC namedpipe
references:
    - https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html
author: 'Samir Bousseaden, @neu5rn'
date: 2020/04/03
modified: 2022/12/27
tags:
    - attack.lateral_movement
    - attack.persistence
    - car.2013-05-004
    - car.2015-04-001
    - attack.t1053.002
logsource:
    product: zeek
    service: smb_files
detection:
    selection:
        path: '\\\*\IPC$'
        name: 'atsvc'
        # Accesses: '*WriteData*'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
