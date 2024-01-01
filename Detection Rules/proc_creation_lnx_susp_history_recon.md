---
title: "Print History File Contents"
status: "test"
created: "2022/06/20"
last_modified: "2022/09/15"
tags: [reconnaissance, t1592_004, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Print History File Contents

### Description

Detects events in which someone prints the contents of history files to the commandline or redirects it to a file for reconnaissance

```yml
title: Print History File Contents
id: d7821ff1-4527-4e33-9f84-d0d57fa2fb66
status: test
description: Detects events in which someone prints the contents of history files to the commandline or redirects it to a file for reconnaissance
references:
    - https://github.com/sleventyeleven/linuxprivchecker/
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.003/T1552.003.md
author: Florian Roth (Nextron Systems)
date: 2022/06/20
modified: 2022/09/15
tags:
    - attack.reconnaissance
    - attack.t1592.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/cat'
            - '/head'
            - '/tail'
            - '/more'
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
level: medium

```
