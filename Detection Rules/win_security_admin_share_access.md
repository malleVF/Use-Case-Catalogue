---
title: "Access to ADMIN$ Share"
status: "test"
created: "2017/03/04"
last_modified: "2021/11/27"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "low"
---

## Access to ADMIN$ Share

### Description

Detects access to $ADMIN share

```yml
title: Access to ADMIN$ Share
id: 098d7118-55bc-4912-a836-dc6483a8d150
status: test
description: Detects access to $ADMIN share
author: Florian Roth (Nextron Systems)
date: 2017/03/04
modified: 2021/11/27
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5140
        ShareName: Admin$
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and not filter
falsepositives:
    - Legitimate administrative activity
level: low

```
