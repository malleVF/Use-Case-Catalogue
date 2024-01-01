---
title: "PowerShell Download and Execution Cradles"
status: "experimental"
created: "2022/03/24"
last_modified: "2023/05/04"
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PowerShell Download and Execution Cradles

### Description

Detects PowerShell download and execution cradles.

```yml
title: PowerShell Download and Execution Cradles
id: 85b0b087-eddf-4a2b-b033-d771fa2b9775
status: experimental
description: Detects PowerShell download and execution cradles.
references:
    - https://github.com/VirtualAlllocEx/Payload-Download-Cradles/blob/88e8eca34464a547c90d9140d70e9866dcbc6a12/Download-Cradles.cmd
    - https://labs.withsecure.com/publications/fin7-target-veeam-servers
author: Florian Roth (Nextron Systems)
date: 2022/03/24
modified: 2023/05/04
tags:
    - attack.execution
    - attack.t1059
logsource:
    product: windows
    category: process_creation
detection:
    selection_download:
        CommandLine|contains:
            - '.DownloadString('
            - '.DownloadFile('
            - 'Invoke-WebRequest '
            - 'iwr '
    selection_iex:
        CommandLine|contains:
            - ';iex $'
            - '| IEX'
            - '|IEX '
            - 'I`E`X'
            - 'I`EX'
            - 'IE`X'
            - 'iex '
            - 'IEX ('
            - 'IEX('
            - 'Invoke-Expression'
    condition: all of selection_*
falsepositives:
    - Some PowerShell installers were seen using similar combinations. Apply filters accordingly
level: high

```