---
title: "Firewall Rule Deleted Via Netsh.EXE"
status: "experimental"
created: "2022/08/14"
last_modified: "2023/02/10"
tags: [defense_evasion, t1562_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Firewall Rule Deleted Via Netsh.EXE

### Description

Detects the removal of a port or application rule in the Windows Firewall configuration using netsh

```yml
title: Firewall Rule Deleted Via Netsh.EXE
id: 1a5fefe6-734f-452e-a07d-fc1c35bce4b2
status: experimental
description: Detects the removal of a port or application rule in the Windows Firewall configuration using netsh
references:
    - https://app.any.run/tasks/8bbd5b4c-b82d-4e6d-a3ea-d454594a37cc/
author: frack113
date: 2022/08/14
modified: 2023/02/10
tags:
    - attack.defense_evasion
    - attack.t1562.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\netsh.exe'
        - OriginalFileName: 'netsh.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'firewall'
            - 'delete '
    filter_optional_dropbox:
        ParentImage|endswith: '\Dropbox.exe'
        CommandLine|contains: 'name=Dropbox'
    condition: all of selection_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate administration activity
    - Software installations and removal
level: medium

```
