---
title: "Empty User Agent"
status: "test"
created: "2017/07/08"
last_modified: "2021/11/27"
tags: [defense_evasion, command_and_control, t1071_001, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "medium"
---

## Empty User Agent

### Description

Detects suspicious empty user agent strings in proxy logs

```yml
title: Empty User Agent
id: 21e44d78-95e7-421b-a464-ffd8395659c4
status: test
description: Detects suspicious empty user agent strings in proxy logs
references:
    - https://twitter.com/Carlos_Perez/status/883455096645931008
author: Florian Roth (Nextron Systems)
date: 2017/07/08
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
      # Empty string - as used by Powershell's (New-Object Net.WebClient).DownloadString
        c-useragent: ''
    condition: selection
fields:
    - ClientIP
    - c-uri
    - c-useragent
falsepositives:
    - Unknown
level: medium

```
