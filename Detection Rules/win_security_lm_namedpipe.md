---
title: "First Time Seen Remote Named Pipe"
status: "test"
created: "2019/04/03"
last_modified: "2023/03/14"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## First Time Seen Remote Named Pipe

### Description

This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes

```yml
title: First Time Seen Remote Named Pipe
id: 52d8b0c6-53d6-439a-9e41-52ad442ad9ad
status: test
description: This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes
references:
    - https://twitter.com/menasec1/status/1104489274387451904
author: Samir Bousseaden
date: 2019/04/03
modified: 2023/03/14
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection1:
        EventID: 5145
        ShareName: '\\\\\*\\IPC$' # looking for the string \\*\IPC$
    false_positives:
        RelativeTargetName:
            - 'atsvc'
            - 'samr'
            - 'lsarpc'
            - 'lsass'
            - 'winreg'
            - 'netlogon'
            - 'srvsvc'
            - 'protected_storage'
            - 'wkssvc'
            - 'browser'
            - 'netdfs'
            - 'svcctl'
            - 'spoolss'
            - 'ntsvcs'
            - 'LSM_API_service'
            - 'HydraLsPipe'
            - 'TermSrv_API_service'
            - 'MsFteWds'
            - 'sql\query'
            - 'eventlog'
    condition: selection1 and not false_positives
falsepositives:
    - Update the excluded named pipe to filter out any newly observed legit named pipe
level: high

```