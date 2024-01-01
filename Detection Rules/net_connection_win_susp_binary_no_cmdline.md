---
title: "Suspicious Network Connection Binary No CommandLine"
status: "test"
created: "2022/07/03"
last_modified: ""
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Network Connection Binary No CommandLine

### Description

Detects suspicious network connections made by a well-known Windows binary run with no command line parameters

```yml
title: Suspicious Network Connection Binary No CommandLine
id: 20384606-a124-4fec-acbb-8bd373728613
status: test
description: Detects suspicious network connections made by a well-known Windows binary run with no command line parameters
references:
    - https://redcanary.com/blog/raspberry-robin/
author: Florian Roth (Nextron Systems)
date: 2022/07/03
tags:
    - attack.defense_evasion
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Initiated: 'true'
        Image|endswith:
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\dllhost.exe'
        CommandLine|endswith:
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\dllhost.exe'
    filter_no_cmdline:
        CommandLine: ''
    filter_null: # e.g. Sysmon has no CommandLine field in network events with ID 3
        CommandLine: null
    condition: selection and not 1 of filter*
falsepositives:
    - Unknown
level: high

```