---
title: "File or Folder Permissions Change"
status: "test"
created: "2019/09/23"
last_modified: "2021/11/27"
tags: [defense_evasion, t1222_002, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "low"
---

## File or Folder Permissions Change

### Description

Detects file and folder permission changes.

```yml
title: File or Folder Permissions Change
id: 74c01ace-0152-4094-8ae2-6fd776dd43e5
status: test
description: Detects file and folder permission changes.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.002/T1222.002.md
author: Jakob Weinzettl, oscd.community
date: 2019/09/23
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.t1222.002
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
        a0|contains:
            - 'chmod'
            - 'chown'
    condition: selection
falsepositives:
    - User interacting with files permissions (normal/daily behaviour).
level: low

```
