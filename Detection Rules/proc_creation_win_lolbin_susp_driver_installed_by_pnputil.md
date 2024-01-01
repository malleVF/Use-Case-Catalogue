---
title: "Suspicious Driver Install by pnputil.exe"
status: "test"
created: "2021/09/30"
last_modified: "2022/10/09"
tags: [persistence, t1547, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Driver Install by pnputil.exe

### Description

Detects when a possible suspicious driver is being installed via pnputil.exe lolbin

```yml
title: Suspicious Driver Install by pnputil.exe
id: a2ea3ae7-d3d0-40a0-a55c-25a45c87cac1
status: test
description: Detects when a possible suspicious driver is being installed via pnputil.exe lolbin
references:
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax
    - https://strontic.github.io/xcyclopedia/library/pnputil.exe-60EDC5E6BDBAEE441F2E3AEACD0340D2.html
author: Hai Vaknin @LuxNoBulIshit, Avihay eldad  @aloneliassaf, Austin Songer @austinsonger
date: 2021/09/30
modified: 2022/10/09
tags:
    - attack.persistence
    - attack.t1547
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-i'
            - '/install'
            - '-a'
            - '/add-driver'
            - '.inf'
        Image|endswith: '\pnputil.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Pnputil.exe being used may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Pnputil.exe being executed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium

```