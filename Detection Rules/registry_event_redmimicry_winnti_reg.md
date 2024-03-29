---
title: "RedMimicry Winnti Playbook Registry Manipulation"
status: "test"
created: "2020/06/24"
last_modified: "2021/11/27"
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## RedMimicry Winnti Playbook Registry Manipulation

### Description

Detects actions caused by the RedMimicry Winnti playbook

```yml
title: RedMimicry Winnti Playbook Registry Manipulation
id: 5b175490-b652-4b02-b1de-5b5b4083c5f8
status: test
description: Detects actions caused by the RedMimicry Winnti playbook
references:
    - https://redmimicry.com
author: Alexander Rausch
date: 2020/06/24
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains: HKLM\SOFTWARE\Microsoft\HTMLHelp\data
    condition: selection
falsepositives:
    - Unknown
level: high

```
