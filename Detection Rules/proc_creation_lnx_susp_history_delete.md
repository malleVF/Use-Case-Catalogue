---
title: "History File Deletion"
status: "test"
created: "2022/06/20"
last_modified: "2022/09/15"
tags: [impact, t1565_001, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "high"
---

## History File Deletion

### Description

Detects events in which a history file gets deleted, e.g. the ~/bash_history to remove traces of malicious activity

```yml
title: History File Deletion
id: 1182f3b3-e716-4efa-99ab-d2685d04360f
status: test
description: Detects events in which a history file gets deleted, e.g. the ~/bash_history to remove traces of malicious activity
references:
    - https://github.com/sleventyeleven/linuxprivchecker/
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md
author: Florian Roth (Nextron Systems)
date: 2022/06/20
modified: 2022/09/15
tags:
    - attack.impact
    - attack.t1565.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/rm'
            - '/unlink'
            - '/shred'
    selection_history:
        - CommandLine|contains:
              - '/.bash_history'
              - '/.zsh_history'
        - CommandLine|endswith:
              - '_history'
              - '.history'
              - 'zhistory'
    condition: all of selection*
falsepositives:
    - Legitimate administration activities
level: high

```
