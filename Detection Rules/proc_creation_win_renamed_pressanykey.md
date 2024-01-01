---
title: "Visual Studio NodejsTools PressAnyKey Renamed Execution"
status: "test"
created: "2023/04/11"
last_modified: ""
tags: [execution, defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Visual Studio NodejsTools PressAnyKey Renamed Execution

### Description

Detects renamed execution of "Microsoft.NodejsTools.PressAnyKey.exe", which can be abused as a LOLBIN to execute arbitrary binaries

```yml
title: Visual Studio NodejsTools PressAnyKey Renamed Execution
id: 65c3ca2c-525f-4ced-968e-246a713d164f
related:
    - id: a20391f8-76fb-437b-abc0-dba2df1952c6
      type: similar
status: test
description: Detects renamed execution of "Microsoft.NodejsTools.PressAnyKey.exe", which can be abused as a LOLBIN to execute arbitrary binaries
references:
    - https://twitter.com/mrd0x/status/1463526834918854661
    - https://gist.github.com/nasbench/a989ce64cefa8081bd50cf6ad8c491b5
author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
date: 2023/04/11
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'Microsoft.NodejsTools.PressAnyKey.exe'
    filter_main_legit_name:
        Image|endswith: '\Microsoft.NodejsTools.PressAnyKey.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium

```
