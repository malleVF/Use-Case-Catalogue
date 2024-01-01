---
title: "Visual Studio Code Tunnel Service Installation"
status: "experimental"
created: "2023/10/25"
last_modified: ""
tags: [command_and_control, t1071_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Visual Studio Code Tunnel Service Installation

### Description

Detects the installation of VsCode tunnel (code-tunnel) as a service.

```yml
title: Visual Studio Code Tunnel Service Installation
id: 30bf1789-379d-4fdc-900f-55cd0a90a801
status: experimental
description: Detects the installation of VsCode tunnel (code-tunnel) as a service.
references:
    - https://ipfyx.fr/post/visual-studio-code-tunnel/
    - https://badoption.eu/blog/2023/01/31/code_c2.html
    - https://code.visualstudio.com/docs/remote/tunnels
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/10/25
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'tunnel '
            - 'service'
            - 'internal-run'
            - 'tunnel-service.log'
    condition: selection
falsepositives:
    - Legitimate installation of code-tunnel as a service
level: medium

```