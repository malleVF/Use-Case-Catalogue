---
title: "SCM Database Handle Failure"
status: "test"
created: "2019/08/12"
last_modified: "2022/07/11"
tags: [discovery, t1010, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## SCM Database Handle Failure

### Description

Detects non-system users failing to get a handle of the SCM database.

```yml
title: SCM Database Handle Failure
id: 13addce7-47b2-4ca0-a98f-1de964d1d669
status: test
description: Detects non-system users failing to get a handle of the SCM database.
references:
    - https://threathunterplaybook.com/hunts/windows/190826-RemoteSCMHandle/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g
date: 2019/08/12
modified: 2022/07/11
tags:
    - attack.discovery
    - attack.t1010
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4656
        ObjectType: 'SC_MANAGER OBJECT'
        ObjectName: 'ServicesActive'
        AccessMask: '0xf003f'  # is used in the reference; otherwise too many FPs
        # Keywords: 'Audit Failure' <-> in the ref 'Keywords':-9214364837600034816
    filter:
        SubjectLogonId: '0x3e4'
    condition: selection and not filter
falsepositives:
    - Unknown
# triggering on many hosts in some environments
level: medium

```
