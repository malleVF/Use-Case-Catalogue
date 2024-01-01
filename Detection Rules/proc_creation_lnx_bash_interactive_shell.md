---
title: "Bash Interactive Shell"
status: "experimental"
created: "2023/04/07"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "low"
---

## Bash Interactive Shell

### Description

Detects execution of the bash shell with the interactive flag "-i".

```yml
title: Bash Interactive Shell
id: 6104e693-a7d6-4891-86cb-49a258523559
status: experimental
description: Detects execution of the bash shell with the interactive flag "-i".
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
    - https://linux.die.net/man/1/bash
author: '@d4ns4n_'
date: 2023/04/07
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/bash'
        CommandLine|contains: ' -i '
    condition: selection
falsepositives:
    - Unknown
level: low

```
