---
title: "Remote Access Tool - ScreenConnect Backstage Mode Anomaly"
status: "experimental"
created: "2022/02/25"
last_modified: "2023/03/05"
tags: [command_and_control, t1219, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Remote Access Tool - ScreenConnect Backstage Mode Anomaly

### Description

Detects suspicious sub processes started by the ScreenConnect client service, which indicates the use of the so-called Backstage mode

```yml
title: Remote Access Tool - ScreenConnect Backstage Mode Anomaly
id: 7b582f1a-b318-4c6a-bf4e-66fe49bf55a5
status: experimental
description: Detects suspicious sub processes started by the ScreenConnect client service, which indicates the use of the so-called Backstage mode
references:
    - https://www.mandiant.com/resources/telegram-malware-iranian-espionage
    - https://docs.connectwise.com/ConnectWise_Control_Documentation/Get_started/Host_client/View_menu/Backstage_mode
author: Florian Roth (Nextron Systems)
date: 2022/02/25
modified: 2023/03/05
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: 'ScreenConnect.ClientService.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    condition: selection
falsepositives:
    - Case in which administrators are allowed to use ScreenConnect's Backstage mode
level: high

```