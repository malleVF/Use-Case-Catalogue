---
title: "Ntdsutil Abuse"
status: "test"
created: "2022/08/14"
last_modified: ""
tags: [credential_access, t1003_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "application"
level: "medium"
---

## Ntdsutil Abuse

### Description

Detects potential abuse of ntdsutil to dump ntds.dit database

```yml
title: Ntdsutil Abuse
id: e6e88853-5f20-4c4a-8d26-cd469fd8d31f
status: test
description: Detects potential abuse of ntdsutil to dump ntds.dit database
references:
    - https://twitter.com/mgreen27/status/1558223256704122882
    - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj574207(v=ws.11)
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/14
tags:
    - attack.credential_access
    - attack.t1003.003
logsource:
    product: windows
    service: application
    # warning: The 'data' field used in the detection section is the container for the event data as a whole. You may have to adapt the rule for your backend accordingly
detection:
    selection:
        Provider_Name: 'ESENT'
        EventID:
            - 216
            - 325
            - 326
            - 327
        Data|contains: 'ntds.dit'
    condition: selection
falsepositives:
    - Legitimate backup operation/creating shadow copies
level: medium

```