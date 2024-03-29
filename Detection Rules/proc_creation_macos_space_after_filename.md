---
title: "Space After Filename - macOS"
status: "test"
created: "2021/11/20"
last_modified: "2023/01/04"
tags: [defense_evasion, t1036_006, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "low"
---

## Space After Filename - macOS

### Description

Detects attempts to masquerade as legitimate files by adding a space to the end of the filename.

```yml
title: Space After Filename - macOS
id: b6e2a2e3-2d30-43b1-a4ea-071e36595690
status: test
description: Detects attempts to masquerade as legitimate files by adding a space to the end of the filename.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1036.006/T1036.006.md
author: remotephone
date: 2021/11/20
modified: 2023/01/04
tags:
    - attack.defense_evasion
    - attack.t1036.006
logsource:
    product: macos
    category: process_creation
detection:
    selection1:
        CommandLine|endswith: ' '
    selection2:
        Image|endswith: ' '
    condition: 1 of selection*
falsepositives:
    - Mistyped commands or legitimate binaries named to match the pattern
level: low

```
