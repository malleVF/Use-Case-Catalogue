---
title: "Remote Access Tool - AnyDesk Silent Installation"
status: "test"
created: "2021/08/06"
last_modified: "2023/03/05"
tags: [command_and_control, t1219, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Remote Access Tool - AnyDesk Silent Installation

### Description

Detects AnyDesk Remote Desktop silent installation. Which can be used by attackers to gain remote access.

```yml
title: Remote Access Tool - AnyDesk Silent Installation
id: 114e7f1c-f137-48c8-8f54-3088c24ce4b9
status: test
description: Detects AnyDesk Remote Desktop silent installation. Which can be used by attackers to gain remote access.
references:
    - https://twitter.com/TheDFIRReport/status/1423361119926816776?s=20
    - https://support.anydesk.com/Automatic_Deployment
author: Ján Trenčanský
date: 2021/08/06
modified: 2023/03/05
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '--install'
            - '--start-with-win'
            - '--silent'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
    - CurrentDirectory
falsepositives:
    - Legitimate deployment of AnyDesk
level: high

```