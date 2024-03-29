---
title: "Interactive Bash Suspicious Children"
status: "test"
created: "2022/03/14"
last_modified: ""
tags: [execution, defense_evasion, t1059_004, t1036, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Interactive Bash Suspicious Children

### Description

Detects suspicious interactive bash as a parent to rather uncommon child processes

```yml
title: Interactive Bash Suspicious Children
id: ea3ecad2-db86-4a89-ad0b-132a10d2db55
status: test
description: Detects suspicious interactive bash as a parent to rather uncommon child processes
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2022/03/14
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059.004
    - attack.t1036
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        ParentCommandLine: 'bash -i'
    anomaly1:
        CommandLine|contains:
            - '-c import '
            - 'base64'
            - 'pty.spawn'
    anomaly2:
        Image|endswith:
            - 'whoami'
            - 'iptables'
            - '/ncat'
            - '/nc'
            - '/netcat'
    condition: selection and 1 of anomaly*
falsepositives:
    - Legitimate software that uses these patterns
level: medium

```
