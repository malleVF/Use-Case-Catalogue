---
title: "Dism Remove Online Package"
status: "test"
created: "2022/01/16"
last_modified: "2022/08/26"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Dism Remove Online Package

### Description

Deployment Image Servicing and Management tool. DISM is used to enumerate, install, uninstall, configure, and update features and packages in Windows images

```yml
title: Dism Remove Online Package
id: 43e32da2-fdd0-4156-90de-50dfd62636f9
status: test
description: Deployment Image Servicing and Management tool. DISM is used to enumerate, install, uninstall, configure, and update features and packages in Windows images
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md#atomic-test-26---disable-windows-defender-with-dism
    - https://www.trendmicro.com/en_us/research/22/h/ransomware-actor-abuses-genshin-impact-anti-cheat-driver-to-kill-antivirus.html
author: frack113
date: 2022/01/16
modified: 2022/08/26
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_dismhost:
        Image|endswith: '\DismHost.exe'
        ParentCommandLine|contains|all:
            - '/Online'
            - '/Disable-Feature'
            # - '/FeatureName:'
            # - '/Remove'
            # /NoRestart
            # /quiet
    selection_dism:
        Image|endswith: '\Dism.exe'
        CommandLine|contains|all:
            - '/Online'
            - '/Disable-Feature'
            # - '/FeatureName:'
            # - '/Remove'
            # /NoRestart
            # /quiet
    condition: 1 of selection_*
falsepositives:
    - Legitimate script
level: medium

```