---
title: "DCERPC SMB Spoolss Named Pipe"
status: "test"
created: "2018/11/28"
last_modified: "2022/08/11"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## DCERPC SMB Spoolss Named Pipe

### Description

Detects the use of the spoolss named pipe over SMB. This can be used to trigger the authentication via NTLM of any machine that has the spoolservice enabled.

```yml
title: DCERPC SMB Spoolss Named Pipe
id: 214e8f95-100a-4e04-bb31-ef6cba8ce07e
status: test
description: Detects the use of the spoolss named pipe over SMB. This can be used to trigger the authentication via NTLM of any machine that has the spoolservice enabled.
references:
    - https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
    - https://dirkjanm.io/a-different-way-of-abusing-zerologon/
    - https://twitter.com/_dirkjan/status/1309214379003588608
author: OTR (Open Threat Research)
date: 2018/11/28
modified: 2022/08/11
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        ShareName: '\\\\\*\\IPC$' # looking for the string \\*\IPC$
        RelativeTargetName: spoolss
    condition: selection
falsepositives:
    - 'Domain Controllers acting as printer servers too? :)'
level: medium

```
