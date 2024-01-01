---
title: "Visual Studio Code Tunnel Execution"
status: "experimental"
created: "2023/10/25"
last_modified: ""
tags: [command_and_control, t1071_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Visual Studio Code Tunnel Execution

### Description

Detects Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel

```yml
title: Visual Studio Code Tunnel Execution
id: 90d6bd71-dffb-4989-8d86-a827fedd6624
status: experimental
description: Detects Visual Studio Code tunnel execution. Attackers can abuse this functionality to establish a C2 channel
references:
    - https://ipfyx.fr/post/visual-studio-code-tunnel/
    - https://badoption.eu/blog/2023/01/31/code_c2.html
    - https://code.visualstudio.com/docs/remote/tunnels
author: Nasreddine Bencherchali (Nextron Systems), citron_ninja
date: 2023/10/25
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_only_tunnel:
        OriginalFileName: null
        CommandLine|endswith: '.exe tunnel'
    selection_tunnel_args:
        CommandLine|contains|all:
            - '.exe tunnel'
            - '--name '
            - '--accept-server-license-terms'
    selection_parent_tunnel:
        ParentCommandLine|endswith: ' tunnel'
        Image|endswith: '\cmd.exe'
        CommandLine|contains|all:
            - '/d /c '
            - '\servers\Stable-'
            - 'code-server.cmd'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Visual Studio Code tunnel
level: medium

```
