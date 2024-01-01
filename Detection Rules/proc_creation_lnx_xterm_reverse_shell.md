---
title: "Potential Xterm Reverse Shell"
status: "experimental"
created: "2023/04/24"
last_modified: ""
tags: [execution, t1059, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Potential Xterm Reverse Shell

### Description

Detects usage of "xterm" as a potential reverse shell tunnel

```yml
title: Potential Xterm Reverse Shell
id: 4e25af4b-246d-44ea-8563-e42aacab006b
status: experimental
description: Detects usage of "xterm" as a potential reverse shell tunnel
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
author: '@d4ns4n_'
date: 2023/04/24
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|contains: 'xterm'
        CommandLine|contains: '-display'
        CommandLine|endswith: ':1'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
