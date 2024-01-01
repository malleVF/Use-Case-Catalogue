---
title: "Suspicious Splwow64 Without Params"
status: "test"
created: "2021/08/23"
last_modified: "2022/12/25"
tags: [defense_evasion, t1202, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Splwow64 Without Params

### Description

Detects suspicious Splwow64.exe process without any command line parameters

```yml
title: Suspicious Splwow64 Without Params
id: 1f1a8509-2cbb-44f5-8751-8e1571518ce2
status: test
description: Detects suspicious Splwow64.exe process without any command line parameters
references:
    - https://twitter.com/sbousseaden/status/1429401053229891590?s=12
author: Florian Roth (Nextron Systems)
date: 2021/08/23
modified: 2022/12/25
tags:
    - attack.defense_evasion
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\splwow64.exe'
        CommandLine|endswith: 'splwow64.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```