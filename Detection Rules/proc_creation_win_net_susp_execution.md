---
title: "Net.exe Execution"
status: "test"
created: "2019/01/16"
last_modified: "2022/07/11"
tags: [discovery, t1007, t1049, t1018, t1135, t1201, t1069_001, t1069_002, t1087_001, t1087_002, lateral_movement, t1021_002, s0039, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Net.exe Execution

### Description

Detects execution of Net.exe, whether suspicious or benign.

```yml
title: Net.exe Execution
id: 183e7ea8-ac4b-4c23-9aec-b3dac4e401ac
status: test
description: Detects execution of Net.exe, whether suspicious or benign.
references:
    - https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
    - https://eqllib.readthedocs.io/en/latest/analytics/4d2e7fc1-af0b-4915-89aa-03d25ba7805e.html
    - https://eqllib.readthedocs.io/en/latest/analytics/e61f557c-a9d0-4c25-ab5b-bbc46bb24deb.html
    - https://eqllib.readthedocs.io/en/latest/analytics/9b3dd402-891c-4c4d-a662-28947168ce61.html
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1007/T1007.md#atomic-test-2---system-service-discovery---netexe
author: Michael Haag, Mark Woan (improvements), James Pemberton / @4A616D6573 / oscd.community (improvements)
date: 2019/01/16
modified: 2022/07/11
tags:
    - attack.discovery
    - attack.t1007
    - attack.t1049
    - attack.t1018
    - attack.t1135
    - attack.t1201
    - attack.t1069.001
    - attack.t1069.002
    - attack.t1087.001
    - attack.t1087.002
    - attack.lateral_movement
    - attack.t1021.002
    - attack.s0039
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
    selection_cli:
        CommandLine|contains:
            - ' group'
            - ' localgroup'
            - ' user'
            - ' view'
            - ' share'
            - ' accounts'
            - ' stop '
            - ' start'
    condition: all of selection_*
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Will need to be tuned. If using Splunk, I recommend | stats count by Computer,CommandLine following the search for easy hunting by computer/CommandLine.
level: low

```
