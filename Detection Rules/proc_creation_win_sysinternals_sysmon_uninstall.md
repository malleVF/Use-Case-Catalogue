---
title: "Uninstall Sysinternals Sysmon"
status: "test"
created: "2022/01/12"
last_modified: "2023/03/09"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Uninstall Sysinternals Sysmon

### Description

Detects the removal of Sysmon, which could be a potential attempt at defense evasion

```yml
title: Uninstall Sysinternals Sysmon
id: 6a5f68d1-c4b5-46b9-94ee-5324892ea939
status: test
description: Detects the removal of Sysmon, which could be a potential attempt at defense evasion
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md#atomic-test-11---uninstall-sysmon
author: frack113
date: 2022/01/12
modified: 2023/03/09
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_pe:
        - Image|endswith:
              - \Sysmon64.exe
              - \Sysmon.exe
        - Description: 'System activity monitor'
    selection_cli:
        CommandLine|contains:
            - '-u'
            - '/u'
    condition: all of selection_*
falsepositives:
    - Legitimate administrators might use this command to remove Sysmon for debugging purposes
level: high

```
