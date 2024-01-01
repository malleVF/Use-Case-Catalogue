---
title: "HackTool - Bloodhound/Sharphound Execution"
status: "test"
created: "2019/12/20"
last_modified: "2023/02/04"
tags: [discovery, t1087_001, t1087_002, t1482, t1069_001, t1069_002, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## HackTool - Bloodhound/Sharphound Execution

### Description

Detects command line parameters used by Bloodhound and Sharphound hack tools

```yml
title: HackTool - Bloodhound/Sharphound Execution
id: f376c8a7-a2d0-4ddc-aa0c-16c17236d962
status: test
description: Detects command line parameters used by Bloodhound and Sharphound hack tools
references:
    - https://github.com/BloodHoundAD/BloodHound
    - https://github.com/BloodHoundAD/SharpHound
author: Florian Roth (Nextron Systems)
date: 2019/12/20
modified: 2023/02/04
tags:
    - attack.discovery
    - attack.t1087.001
    - attack.t1087.002
    - attack.t1482
    - attack.t1069.001
    - attack.t1069.002
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Product|contains: 'SharpHound'
        - Description|contains: 'SharpHound'
        - Company|contains:
              - 'SpecterOps'
              - 'evil corp'
        - Image|contains:
              - '\Bloodhound.exe'
              - '\SharpHound.exe'
    selection_cli_1:
        CommandLine|contains:
            - ' -CollectionMethod All '
            - ' --CollectionMethods Session '
            - ' --Loop --Loopduration '
            - ' --PortScanTimeout '
            - '.exe -c All -d '
            - 'Invoke-Bloodhound'
            - 'Get-BloodHoundData'
    selection_cli_2:
        CommandLine|contains|all:
            - ' -JsonFolder '
            - ' -ZipFileName '
    selection_cli_3:
        CommandLine|contains|all:
            - ' DCOnly '
            - ' --NoSaveCache '
    condition: 1 of selection_*
falsepositives:
    - Other programs that use these command line option and accepts an 'All' parameter
level: high

```
