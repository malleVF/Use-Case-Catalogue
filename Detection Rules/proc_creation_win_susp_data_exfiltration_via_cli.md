---
title: "Potential Data Exfiltration Activity Via CommandLine Tools"
status: "experimental"
created: "2022/08/02"
last_modified: "2023/07/27"
tags: [execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Data Exfiltration Activity Via CommandLine Tools

### Description

Detects the use of various CLI utilities exfiltrating data via web requests

```yml
title: Potential Data Exfiltration Activity Via CommandLine Tools
id: 7d1aaf3d-4304-425c-b7c3-162055e0b3ab
status: experimental
description: Detects the use of various CLI utilities exfiltrating data via web requests
references:
    - https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/02
modified: 2023/07/27
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_iwr:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'iwr '
            - 'wget '
            - 'curl '
        CommandLine|contains|all:
            - ' -ur' # Shortest possible version of the -uri flag
            - ' -me' # Shortest possible version of the -method flag
            - ' -b'
            - ' POST '
    selection_curl:
        Image|endswith: '\curl.exe'
        CommandLine|contains: '--ur' # Shortest possible version of the --uri flag
    selection_curl_data:
        CommandLine|contains:
            - ' -d ' # Shortest possible version of the --data flag
            - ' --data '
    selection_wget:
        Image|endswith: '\wget.exe'
        CommandLine|contains:
            - '--post-data'
            - '--post-file'
    payloads:
        - CommandLine|contains:
              - 'Get-Content'
              - 'GetBytes'
              - 'hostname'
              - 'ifconfig'
              - 'ipconfig'
              - 'net view'
              - 'netstat'
              - 'nltest'
              - 'qprocess'
              - 'sc query'
              - 'systeminfo'
              - 'tasklist'
              - 'ToBase64String'
              - 'whoami'
        - CommandLine|contains|all:
              - 'type '
              - ' > '
              - ' C:\'
    condition: (selection_iwr or all of selection_curl* or selection_wget) and payloads
falsepositives:
    - Unlikely
level: high

```