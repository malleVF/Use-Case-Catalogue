---
title: "Indicator Removal on Host - Clear Mac System Logs"
status: "test"
created: "2020/10/11"
last_modified: "2022/09/16"
tags: [defense_evasion, t1070_002, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "medium"
---

## Indicator Removal on Host - Clear Mac System Logs

### Description

Detects deletion of local audit logs

```yml
title: Indicator Removal on Host - Clear Mac System Logs
id: acf61bd8-d814-4272-81f0-a7a269aa69aa
status: test
description: Detects deletion of local audit logs
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.002/T1070.002.md
author: remotephone, oscd.community
date: 2020/10/11
modified: 2022/09/16
tags:
    - attack.defense_evasion
    - attack.t1070.002
logsource:
    product: macos
    category: process_creation
detection:
    selection1:
        Image|endswith:
            - '/rm'
            - '/unlink'
            - '/shred'
    selection_cli_1:
        CommandLine|contains: '/var/log'
    selection_cli_2:
        CommandLine|contains|all:
            - '/Users/'
            - '/Library/Logs/'
    condition: selection1 and 1 of selection_cli*
falsepositives:
    - Legitimate administration activities
level: medium

```
