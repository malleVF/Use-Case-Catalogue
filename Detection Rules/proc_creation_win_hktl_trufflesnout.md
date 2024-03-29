---
title: "HackTool - TruffleSnout Execution"
status: "experimental"
created: "2022/08/20"
last_modified: "2023/02/13"
tags: [discovery, t1482, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - TruffleSnout Execution

### Description

Detects the use of TruffleSnout.exe an iterative AD discovery toolkit for offensive operators, situational awareness and targeted low noise enumeration.

```yml
title: HackTool - TruffleSnout Execution
id: 69ca006d-b9a9-47f5-80ff-ecd4d25d481a
status: experimental
description: Detects the use of TruffleSnout.exe an iterative AD discovery toolkit for offensive operators, situational awareness and targeted low noise enumeration.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1482/T1482.md
    - https://github.com/dsnezhkov/TruffleSnout
    - https://github.com/dsnezhkov/TruffleSnout/blob/master/TruffleSnout/Docs/USAGE.md
author: frack113
date: 2022/08/20
modified: 2023/02/13
tags:
    - attack.discovery
    - attack.t1482
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - OriginalFileName: 'TruffleSnout.exe'
        - Image|endswith: '\TruffleSnout.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
