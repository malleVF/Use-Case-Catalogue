---
title: "Telegram API Access"
status: "test"
created: "2018/06/05"
last_modified: "2023/05/18"
tags: [defense_evasion, command_and_control, t1071_001, t1102_002, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "medium"
---

## Telegram API Access

### Description

Detects suspicious requests to Telegram API without the usual Telegram User-Agent

```yml
title: Telegram API Access
id: b494b165-6634-483d-8c47-2026a6c52372
status: test
description: Detects suspicious requests to Telegram API without the usual Telegram User-Agent
references:
    - https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/
    - https://blog.malwarebytes.com/threat-analysis/2016/11/telecrypt-the-ransomware-abusing-telegram-api-defeated/
    - https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/
author: Florian Roth (Nextron Systems)
date: 2018/06/05
modified: 2023/05/18
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1102.002
logsource:
    category: proxy
detection:
    selection:
        cs-host: 'api.telegram.org' # Often used by Bots
    filter:
        c-useragent|contains:
            # Used https://core.telegram.org/bots/samples for this list
            - 'Telegram'
            - 'Bot'
    condition: selection and not filter
fields:
    - ClientIP
    - c-uri
    - c-useragent
falsepositives:
    - Legitimate use of Telegram bots in the company
level: medium

```
