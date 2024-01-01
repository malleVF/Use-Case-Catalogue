---
title: "Service Installed By Unusual Client - Security"
status: "test"
created: "2022/09/15"
last_modified: "2023/01/04"
tags: [privilege_escalation, t1543, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Service Installed By Unusual Client - Security

### Description

Detects a service installed by a client which has PID 0 or whose parent has PID 0

```yml
title: Service Installed By Unusual Client - Security
id: c4e92a97-a9ff-4392-9d2d-7a4c642768ca
related:
    - id: 71c276aa-49cd-43d2-b920-2dcd3e6962d5
      type: similar
status: test
description: Detects a service installed by a client which has PID 0 or whose parent has PID 0
references:
    - https://www.elastic.co/guide/en/security/current/windows-service-installed-via-an-unusual-client.html
    - https://www.x86matthew.com/view_post?id=create_svc_rpc
    - https://twitter.com/SBousseaden/status/1490608838701166596
author: Tim Rauch (Nextron Systems), Elastic
date: 2022/09/15
modified: 2023/01/04
tags:
    - attack.privilege_escalation
    - attack.t1543
logsource:
    service: security
    product: windows
    definition: 'Requirements: The System Security Extension audit subcategory need to be enabled to log the EID 4697'
detection:
    selection_eid:
        EventID: 4697
    selection_pid:
        - ClientProcessId: 0
        - ParentProcessId: 0
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
