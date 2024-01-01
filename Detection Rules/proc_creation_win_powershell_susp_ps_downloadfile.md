---
title: "PowerShell DownloadFile"
status: "test"
created: "2020/08/28"
last_modified: "2021/11/27"
tags: [execution, t1059_001, command_and_control, t1104, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PowerShell DownloadFile

### Description

Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line

```yml
title: PowerShell DownloadFile
id: 8f70ac5f-1f6f-4f8e-b454-db19561216c5
status: test
description: Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line
references:
    - https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html
author: Florian Roth (Nextron Systems)
date: 2020/08/28
modified: 2021/11/27
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command_and_control
    - attack.t1104
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - '.DownloadFile'
            - 'System.Net.WebClient'
    condition: selection
falsepositives:
    - Unknown
level: high

```