---
title: "Equation Editor Network Connection"
status: "test"
created: "2022/04/14"
last_modified: ""
tags: [execution, t1203, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Equation Editor Network Connection

### Description

Detects network connections from Equation Editor

```yml
title: Equation Editor Network Connection
id: a66bc059-c370-472c-a0d7-f8fd1bf9d583
status: test
description: Detects network connections from Equation Editor
references:
    - https://twitter.com/forensicitguy/status/1513538712986079238
    - https://news.sophos.com/en-us/2019/07/18/a-new-equation-editor-exploit-goes-commercial-as-maldoc-attacks-using-it-spike/
author: Max Altgelt (Nextron Systems)
date: 2022/04/14
tags:
    - attack.execution
    - attack.t1203
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\eqnedt32.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```