---
title: "Potential Regsvr32 Commandline Flag Anomaly"
status: "test"
created: "2019/07/13"
last_modified: "2023/05/26"
tags: [defense_evasion, t1218_010, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Regsvr32 Commandline Flag Anomaly

### Description

Detects a potential command line flag anomaly related to "regsvr32" in which the "/i" flag is used without the "/n" which should be uncommon.

```yml
title: Potential Regsvr32 Commandline Flag Anomaly
id: b236190c-1c61-41e9-84b3-3fe03f6d76b0
status: test
description: Detects a potential command line flag anomaly related to "regsvr32" in which the "/i" flag is used without the "/n" which should be uncommon.
references:
    - https://twitter.com/sbousseaden/status/1282441816986484737?s=12
author: Florian Roth (Nextron Systems)
date: 2019/07/13
modified: 2023/05/26
tags:
    - attack.defense_evasion
    - attack.t1218.010
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains:
            - ' /i:'
            - ' -i:'
    filter_main_flag:
        CommandLine|contains:
            - ' /n '
            - ' -n '
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Administrator typo might cause some false positives
level: medium

```
