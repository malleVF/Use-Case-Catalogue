---
title: "Use of Scriptrunner.exe"
status: "test"
created: "2022/07/01"
last_modified: ""
tags: [defense_evasion, execution, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Use of Scriptrunner.exe

### Description

The "ScriptRunner.exe" binary can be abused to proxy execution through it and bypass possible whitelisting

```yml
title: Use of Scriptrunner.exe
id: 64760eef-87f7-4ed3-93fd-655668ea9420
status: test
description: The "ScriptRunner.exe" binary can be abused to proxy execution through it and bypass possible whitelisting
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Scriptrunner/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/07/01
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\ScriptRunner.exe'
        - OriginalFileName: 'ScriptRunner.exe'
    selection_cli:
        CommandLine|contains: ' -appvscript '
    condition: all of selection*
falsepositives:
    - Legitimate use when App-v is deployed
level: medium

```