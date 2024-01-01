---
title: "Narrator's Feedback-Hub Persistence"
status: "test"
created: "2019/10/25"
last_modified: "2022/03/26"
tags: [persistence, t1547_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Narrator's Feedback-Hub Persistence

### Description

Detects abusing Windows 10 Narrator's Feedback-Hub

```yml
title: Narrator's Feedback-Hub Persistence
id: f663a6d9-9d1b-49b8-b2b1-0637914d199a
status: test
description: Detects abusing Windows 10 Narrator's Feedback-Hub
references:
    - https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html
author: Dmitriy Lifanov, oscd.community
date: 2019/10/25
modified: 2022/03/26
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_event
    product: windows
detection:
    selection1:
        EventType: DeleteValue
        TargetObject|endswith: '\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\DelegateExecute'
    selection2:
        TargetObject|endswith: '\AppXypsaf9f1qserqevf0sws76dx4k9a5206\Shell\open\command\(Default)'
    # Add the payload in the (Default)
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high

```