---
title: "Remove Immutable File Attribute - Auditd"
status: "test"
created: "2019/09/23"
last_modified: "2022/11/26"
tags: [defense_evasion, t1222_002, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "medium"
---

## Remove Immutable File Attribute - Auditd

### Description

Detects removing immutable file attribute.

```yml
title: Remove Immutable File Attribute - Auditd
id: a5b977d6-8a81-4475-91b9-49dbfcd941f7
status: test
description: Detects removing immutable file attribute.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.002/T1222.002.md
author: Jakob Weinzettl, oscd.community
date: 2019/09/23
modified: 2022/11/26
tags:
    - attack.defense_evasion
    - attack.t1222.002
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
        a0|contains: 'chattr'
        a1|contains: '-i'
    condition: selection
falsepositives:
    - Administrator interacting with immutable files (e.g. for instance backups).
level: medium

```
