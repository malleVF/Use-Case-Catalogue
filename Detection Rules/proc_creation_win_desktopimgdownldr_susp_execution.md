---
title: "Suspicious Desktopimgdownldr Command"
status: "test"
created: "2020/07/03"
last_modified: "2021/11/27"
tags: [command_and_control, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Desktopimgdownldr Command

### Description

Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet

```yml
title: Suspicious Desktopimgdownldr Command
id: bb58aa4a-b80b-415a-a2c0-2f65a4c81009
status: test
description: Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet
references:
    - https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
    - https://twitter.com/SBousseaden/status/1278977301745741825
author: Florian Roth (Nextron Systems)
date: 2020/07/03
modified: 2021/11/27
tags:
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: ' /lockscreenurl:'
    selection1_filter:
        CommandLine|contains:
            - '.jpg'
            - '.jpeg'
            - '.png'
    selection_reg:
        CommandLine|contains|all:
            - 'reg delete'
            - '\PersonalizationCSP'
    condition: ( selection1 and not selection1_filter ) or selection_reg
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high

```