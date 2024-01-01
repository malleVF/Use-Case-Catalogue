---
title: "Gzip Archive Decode Via PowerShell"
status: "experimental"
created: "2023/03/13"
last_modified: ""
tags: [command_and_control, t1132_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Gzip Archive Decode Via PowerShell

### Description

Detects attempts of decoding encoded Gzip archives via PowerShell.

```yml
title: Gzip Archive Decode Via PowerShell
id: 98767d61-b2e8-4d71-b661-e36783ee24c1
status: experimental
description: Detects attempts of decoding encoded Gzip archives via PowerShell.
references:
    - https://www.zscaler.com/blogs/security-research/onenote-growing-threat-malware-distribution
author: Hieu Tran
date: 2023/03/13
tags:
    - attack.command_and_control
    - attack.t1132.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'GZipStream'
            - '::Decompress'
    condition: selection
falsepositives:
    - Legitimate administrative scripts may use this functionality. Use "ParentImage" in combination with the script names and allowed users and applications to filter legitimate executions
level: medium

```
