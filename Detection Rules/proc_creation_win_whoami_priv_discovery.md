---
title: "Security Privileges Enumeration Via Whoami.EXE"
status: "experimental"
created: "2021/05/05"
last_modified: "2023/02/28"
tags: [privilege_escalation, discovery, t1033, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Security Privileges Enumeration Via Whoami.EXE

### Description

Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privileges. This is often used after a privilege escalation attempt.

```yml
title: Security Privileges Enumeration Via Whoami.EXE
id: 97a80ec7-0e2f-4d05-9ef4-65760e634f6b
status: experimental
description: Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privileges. This is often used after a privilege escalation attempt.
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami
author: Florian Roth (Nextron Systems)
date: 2021/05/05
modified: 2023/02/28
tags:
    - attack.privilege_escalation
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\whoami.exe'
        - OriginalFileName: 'whoami.exe'
    selection_cli:
        CommandLine|contains:
            - ' /priv'
            - ' -priv'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
