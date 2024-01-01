---
title: "XSL Script Execution Via WMIC.EXE"
status: "test"
created: "2019/10/21"
last_modified: "2023/11/09"
tags: [defense_evasion, t1220, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## XSL Script Execution Via WMIC.EXE

### Description

Detects the execution of WMIC with the "format" flag to potentially load XSL files.
Adversaries abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses.
Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files.


```yml
title: XSL Script Execution Via WMIC.EXE
id: 05c36dd6-79d6-4a9a-97da-3db20298ab2d
status: test
description: |
    Detects the execution of WMIC with the "format" flag to potentially load XSL files.
    Adversaries abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses.
    Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1220/T1220.md
author: Timur Zinniatullin, oscd.community, Swachchhanda Shrawan Poudel
date: 2019/10/21
modified: 2023/11/09
tags:
    - attack.defense_evasion
    - attack.t1220
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\wmic.exe'
        CommandLine|contains:
            - '/format'     # wmic process list /FORMAT /?
            - '-format'     # wmic process list -FORMAT /?
    filter_main_known_format:
        CommandLine|contains:
            - 'Format:List'
            - 'Format:htable'
            - 'Format:hform'
            - 'Format:table'
            - 'Format:mof'
            - 'Format:value'
            - 'Format:rawxml'
            - 'Format:xml'
            - 'Format:csv'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - WMIC.exe FP depend on scripts and administrative methods used in the monitored environment.
    - Static format arguments - https://petri.com/command-line-wmi-part-3
level: medium

```