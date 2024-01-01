---
title: "Office Application Startup - Office Test"
status: "test"
created: "2020/10/25"
last_modified: "2023/11/08"
tags: [persistence, t1137_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Office Application Startup - Office Test

### Description

Detects the addition of office test registry that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started

```yml
title: Office Application Startup - Office Test
id: 3d27f6dd-1c74-4687-b4fa-ca849d128d1c
status: test
description: Detects the addition of office test registry that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started
references:
    - https://unit42.paloaltonetworks.com/unit42-technical-walkthrough-office-test-persistence-method-used-in-recent-sofacy-attacks/
author: omkar72
date: 2020/10/25
modified: 2023/11/08
tags:
    - attack.persistence
    - attack.t1137.002
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Office test\Special\Perf'
    condition: selection
falsepositives:
    - Unlikely
level: medium

```