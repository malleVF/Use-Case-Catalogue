---
title: "Remote File Copy"
status: "stable"
created: "2020/06/18"
last_modified: ""
tags: [command_and_control, lateral_movement, t1105, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "low"
---

## Remote File Copy

### Description

Detects the use of tools that copy files from or to remote systems

```yml
title: Remote File Copy
id: 7a14080d-a048-4de8-ae58-604ce58a795b
status: stable
description: Detects the use of tools that copy files from or to remote systems
references:
    - https://attack.mitre.org/techniques/T1105/
author: Ömer Günal
date: 2020/06/18
tags:
    - attack.command_and_control
    - attack.lateral_movement
    - attack.t1105
logsource:
    product: linux
detection:
    tools:
        - 'scp '
        - 'rsync '
        - 'sftp '
    filter:
        - '@'
        - ':'
    condition: tools and filter
falsepositives:
    - Legitimate administration activities
level: low

```
