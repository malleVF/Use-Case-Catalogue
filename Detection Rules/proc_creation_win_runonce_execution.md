---
title: "Run Once Task Execution as Configured in Registry"
status: "test"
created: "2020/10/18"
last_modified: "2022/12/13"
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Run Once Task Execution as Configured in Registry

### Description

This rule detects the execution of Run Once task as configured in the registry

```yml
title: Run Once Task Execution as Configured in Registry
id: 198effb6-6c98-4d0c-9ea3-451fa143c45c
status: test
description: This rule detects the execution of Run Once task as configured in the registry
references:
    - https://twitter.com/pabraeken/status/990717080805789697
    - https://lolbas-project.github.io/lolbas/Binaries/Runonce/
    - https://twitter.com/0gtweet/status/1602644163824156672?s=20&t=kuxbUnZPltpvFPZdCrqPXA
author: 'Avneet Singh @v3t0_, oscd.community, Christopher Peacock @SecurePeacock (updated)'
date: 2020/10/18
modified: 2022/12/13
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\runonce.exe'
        - Description: 'Run Once Wrapper'
    selection_cli:
        - CommandLine|contains: '/AlternateShellStartup'
        - CommandLine|endswith: '/r'
    condition: all of selection_*
falsepositives:
    - Unknown
level: low

```