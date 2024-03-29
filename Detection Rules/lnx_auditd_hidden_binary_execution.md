---
title: "Use Of Hidden Paths Or Files"
status: "test"
created: "2022/12/30"
last_modified: ""
tags: [defense_evasion, t1574_001, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "low"
---

## Use Of Hidden Paths Or Files

### Description

Detects calls to hidden files or files located in hidden directories in NIX systems.

```yml
title: Use Of Hidden Paths Or Files
id: 9e1bef8d-0fff-46f6-8465-9aa54e128c1e
related:
    - id: d08722cd-3d09-449a-80b4-83ea2d9d4616
      type: similar
status: test
description: Detects calls to hidden files or files located in hidden directories in NIX systems.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.001/T1564.001.md
author: David Burkett, @signalblur
date: 2022/12/30
tags:
    - attack.defense_evasion
    - attack.t1574.001
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'PATH'
        name|contains: '/.'
    filter:
        name|contains:
            - '/.cache/'
            - '/.config/'
            - '/.pyenv/'
            - '/.rustup/toolchains'
    condition: selection and not filter
falsepositives:
    - Unknown
level: low

```
