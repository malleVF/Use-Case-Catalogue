---
title: "Rundll32 Execution Without CommandLine Parameters"
status: "experimental"
created: "2021/05/27"
last_modified: "2023/08/31"
tags: [defense_evasion, t1202, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Rundll32 Execution Without CommandLine Parameters

### Description

Detects suspicious start of rundll32.exe without any parameters as found in CobaltStrike beacon activity

```yml
title: Rundll32 Execution Without CommandLine Parameters
id: 1775e15e-b61b-4d14-a1a3-80981298085a
status: experimental
description: Detects suspicious start of rundll32.exe without any parameters as found in CobaltStrike beacon activity
references:
    - https://www.cobaltstrike.com/help-opsec
    - https://twitter.com/ber_m1ng/status/1397948048135778309
author: Florian Roth (Nextron Systems)
date: 2021/05/27
modified: 2023/08/31
tags:
    - attack.defense_evasion
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|endswith:
            - '\rundll32.exe'
            - '\rundll32.exe"'
            - '\rundll32'
    filter:
        ParentImage|contains:
            - '\AppData\Local\'
            - '\Microsoft\Edge\'
    condition: selection and not filter
falsepositives:
    - Possible but rare
level: high

```