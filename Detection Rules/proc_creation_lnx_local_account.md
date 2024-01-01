---
title: "Local System Accounts Discovery - Linux"
status: "test"
created: "2020/10/08"
last_modified: "2022/11/27"
tags: [discovery, t1087_001, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "low"
---

## Local System Accounts Discovery - Linux

### Description

Detects enumeration of local systeam accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.

```yml
title: Local System Accounts Discovery - Linux
id: b45e3d6f-42c6-47d8-a478-df6bd6cf534c
status: test
description: Detects enumeration of local systeam accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1087.001/T1087.001.md
author: Alejandro Ortuno, oscd.community
date: 2020/10/08
modified: 2022/11/27
tags:
    - attack.discovery
    - attack.t1087.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_1:
        Image|endswith: '/lastlog'
    selection_2:
        CommandLine|contains: '''x:0:'''
    selection_3:
        Image|endswith:
            - '/cat'
            - '/head'
            - '/tail'
            - '/more'
        CommandLine|contains:
            - '/etc/passwd'
            - '/etc/shadow'
            - '/etc/sudoers'
    selection_4:
        Image|endswith: '/id'
    selection_5:
        Image|endswith: '/lsof'
        CommandLine|contains: '-u'
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: low

```
