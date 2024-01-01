---
title: "Hidden Files and Directories"
status: "test"
created: "2021/09/06"
last_modified: "2022/10/09"
tags: [defense_evasion, t1564_001, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "low"
---

## Hidden Files and Directories

### Description

Detects adversary creating hidden file or directory, by detecting directories or files with . as the first character

```yml
title: Hidden Files and Directories
id: d08722cd-3d09-449a-80b4-83ea2d9d4616
status: test
description: Detects adversary creating hidden file or directory, by detecting directories or files with . as the first character
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.001/T1564.001.md
author: 'Pawel Mazur'
date: 2021/09/06
modified: 2022/10/09
tags:
    - attack.defense_evasion
    - attack.t1564.001
logsource:
    product: linux
    service: auditd
detection:
    commands:
        type: EXECVE
        a0:
            - mkdir
            - touch
            - vim
            - nano
            - vi
    arguments:
        - a1|contains: '/.'
        - a1|startswith: '.'
        - a2|contains: '/.'
        - a2|startswith: '.'
    condition: commands and arguments
falsepositives:
    - Unknown
level: low

```
