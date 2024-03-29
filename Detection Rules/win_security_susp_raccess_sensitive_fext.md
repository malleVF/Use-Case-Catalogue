---
title: "Suspicious Access to Sensitive File Extensions"
status: "test"
created: "2019/04/03"
last_modified: "2022/10/09"
tags: [collection, t1039, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Suspicious Access to Sensitive File Extensions

### Description

Detects known sensitive file extensions accessed on a network share

```yml
title: Suspicious Access to Sensitive File Extensions
id: 91c945bc-2ad1-4799-a591-4d00198a1215
related:
    - id: 286b47ed-f6fe-40b3-b3a8-35129acd43bc
      type: similar
status: test
description: Detects known sensitive file extensions accessed on a network share
author: Samir Bousseaden
date: 2019/04/03
modified: 2022/10/09
tags:
    - attack.collection
    - attack.t1039
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        RelativeTargetName|endswith:
            - '.pst'
            - '.ost'
            - '.msg'
            - '.nst'
            - '.oab'
            - '.edb'
            - '.nsf'
            - '.bak'
            - '.dmp'
            - '.kirbi'
            - '\groups.xml'
            - '.rdp'
    condition: selection
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
    - RelativeTargetName
falsepositives:
    - Help Desk operator doing backup or re-imaging end user machine or backup software
    - Users working with these data types or exchanging message files
level: medium

```
