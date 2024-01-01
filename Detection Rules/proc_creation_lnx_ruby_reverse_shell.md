---
title: "Potential Ruby Reverse Shell"
status: "experimental"
created: "2023/04/07"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "medium"
---

## Potential Ruby Reverse Shell

### Description

Detects execution of ruby with the "-e" flag and calls to "socket" related functions. This could be an indication of a potential attempt to setup a reverse shell

```yml
title: Potential Ruby Reverse Shell
id: b8bdac18-c06e-4016-ac30-221553e74f59
status: experimental
description: Detects execution of ruby with the "-e" flag and calls to "socket" related functions. This could be an indication of a potential attempt to setup a reverse shell
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
author: '@d4ns4n_'
date: 2023/04/07
tags:
    - attack.execution
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|contains: 'ruby'
        CommandLine|contains|all:
            - ' -e'
            - 'rsocket'
            - 'TCPSocket'
        CommandLine|contains:
            - ' ash'
            - ' bash'
            - ' bsh'
            - ' csh'
            - ' ksh'
            - ' pdksh'
            - ' sh'
            - ' tcsh'
    condition: selection
falsepositives:
    - Unknown
level: medium

```