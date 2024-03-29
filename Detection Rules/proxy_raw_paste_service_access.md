---
title: "Raw Paste Service Access"
status: "test"
created: "2019/12/05"
last_modified: "2023/01/19"
tags: [command_and_control, t1071_001, t1102_001, t1102_003, defense_evasion, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## Raw Paste Service Access

### Description

Detects direct access to raw pastes in different paste services often used by malware in their second stages to download malicious code in encrypted or encoded form

```yml
title: Raw Paste Service Access
id: 5468045b-4fcc-4d1a-973c-c9c9578edacb
status: test
description: Detects direct access to raw pastes in different paste services often used by malware in their second stages to download malicious code in encrypted or encoded form
references:
    - https://www.virustotal.com/gui/domain/paste.ee/relations
author: Florian Roth (Nextron Systems)
date: 2019/12/05
modified: 2023/01/19
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1102.001
    - attack.t1102.003
    - attack.defense_evasion
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains:
            - '.paste.ee/r/'
            - '.pastebin.com/raw/'
            - '.hastebin.com/raw/'
            - '.ghostbin.co/paste/*/raw/'
            - 'pastetext.net/'
            - 'pastebin.pl/'
            - 'paste.ee/'
    condition: selection
fields:
    - ClientIP
    - c-uri
    - c-useragent
falsepositives:
    - User activity (e.g. developer that shared and copied code snippets and used the raw link instead of just copy & paste)
level: high

```
