---
title: "Suspicious Cmdl32 Execution"
status: "test"
created: "2021/11/03"
last_modified: "2022/06/12"
tags: [execution, defense_evasion, t1218, t1202, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Cmdl32 Execution

### Description

lolbas Cmdl32 is use to download a payload to evade antivirus

```yml
title: Suspicious Cmdl32 Execution
id: f37aba28-a9e6-4045-882c-d5004043b337
status: test
description: lolbas Cmdl32 is use to download a payload to evade antivirus
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Cmdl32/
    - https://twitter.com/SwiftOnSecurity/status/1455897435063074824
author: frack113
date: 2021/11/03
modified: 2022/06/12
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1218
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\cmdl32.exe'
        - OriginalFileName: CMDL32.EXE
    selection_cli:
        CommandLine|contains|all:
            - '/vpn '
            - '/lan '
    condition: all of selection*
falsepositives:
    - Unknown
level: medium

```
