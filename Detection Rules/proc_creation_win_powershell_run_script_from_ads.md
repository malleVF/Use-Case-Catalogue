---
title: "Run PowerShell Script from ADS"
status: "test"
created: "2019/10/30"
last_modified: "2022/07/14"
tags: [defense_evasion, t1564_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Run PowerShell Script from ADS

### Description

Detects PowerShell script execution from Alternate Data Stream (ADS)

```yml
title: Run PowerShell Script from ADS
id: 45a594aa-1fbd-4972-a809-ff5a99dd81b8
status: test
description: Detects PowerShell script execution from Alternate Data Stream (ADS)
references:
    - https://github.com/p0shkatz/Get-ADS/blob/1c3a3562e713c254edce1995a7d9879c687c7473/Get-ADS.ps1
author: Sergey Soldatov, Kaspersky Lab, oscd.community
date: 2019/10/30
modified: 2022/07/14
tags:
    - attack.defense_evasion
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'Get-Content'
            - '-Stream'
    condition: selection
falsepositives:
    - Unknown
level: high

```
