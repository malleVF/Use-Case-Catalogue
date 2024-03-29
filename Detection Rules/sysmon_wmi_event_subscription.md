---
title: "WMI Event Subscription"
status: "test"
created: "2019/01/12"
last_modified: "2021/11/27"
tags: [persistence, t1546_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## WMI Event Subscription

### Description

Detects creation of WMI event subscription persistence method

```yml
title: WMI Event Subscription
id: 0f06a3a5-6a09-413f-8743-e6cf35561297
status: test
description: Detects creation of WMI event subscription persistence method
author: Tom Ueltschi (@c_APT_ure)
date: 2019/01/12
modified: 2021/11/27
tags:
    - attack.persistence
    - attack.t1546.003
logsource:
    product: windows
    category: wmi_event
detection:
    selection:
        EventID:
            - 19
            - 20
            - 21
    condition: selection
falsepositives:
    - Exclude legitimate (vetted) use of WMI event subscription in your network
level: medium

```
