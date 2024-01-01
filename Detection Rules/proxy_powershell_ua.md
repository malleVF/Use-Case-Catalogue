---
title: "Windows PowerShell User Agent"
status: "test"
created: "2017/03/13"
last_modified: "2021/11/27"
tags: [defense_evasion, command_and_control, t1071_001, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "medium"
---

## Windows PowerShell User Agent

### Description

Detects Windows PowerShell Web Access

```yml
title: Windows PowerShell User Agent
id: c8557060-9221-4448-8794-96320e6f3e74
status: test
description: Detects Windows PowerShell Web Access
references:
    - https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
author: Florian Roth (Nextron Systems)
date: 2017/03/13
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-useragent|contains: ' WindowsPowerShell/'
    condition: selection
fields:
    - ClientIP
    - c-uri
    - c-useragent
falsepositives:
    - Administrative scripts that download files from the Internet
    - Administrative scripts that retrieve certain website contents
level: medium

```
