---
title: "PowerShell Base64 Encoded FromBase64String Cmdlet"
status: "test"
created: "2019/08/24"
last_modified: "2023/04/06"
tags: [defense_evasion, t1140, execution, t1059_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## PowerShell Base64 Encoded FromBase64String Cmdlet

### Description

Detects usage of a base64 encoded "FromBase64String" cmdlet in a process command line

```yml
title: PowerShell Base64 Encoded FromBase64String Cmdlet
id: fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c
status: test
description: Detects usage of a base64 encoded "FromBase64String" cmdlet in a process command line
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2019/08/24
modified: 2023/04/06
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|base64offset|contains: '::FromBase64String'
        # UTF-16 LE
        - CommandLine|contains:
              - 'OgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcA'
              - 'oAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnA'
              - '6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZw'
    condition: selection
falsepositives:
    - Unknown
level: high

```
