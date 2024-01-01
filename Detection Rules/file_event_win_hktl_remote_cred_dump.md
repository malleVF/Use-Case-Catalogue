---
title: "Potential Remote Credential Dumping Activity"
status: "test"
created: "2022/11/16"
last_modified: "2023/01/05"
tags: [credential_access, t1003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential Remote Credential Dumping Activity

### Description

Detects default filenames output from the execution of CrackMapExec and Impacket-secretsdump against an endpoint.

```yml
title: Potential Remote Credential Dumping Activity
id: 6e2a900a-ced9-4e4a-a9c2-13e706f9518a
status: test
description: Detects default filenames output from the execution of CrackMapExec and Impacket-secretsdump against an endpoint.
references:
    - https://github.com/Porchetta-Industries/CrackMapExec
    - https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py
author: SecurityAura
date: 2022/11/16
modified: 2023/01/05
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image|endswith: '\svchost.exe'
        # CommandLine|contains: 'RemoteRegistry' # Uncomment this line if you collect CommandLine data for files events from more accuracy
        TargetFilename|re: '\\Windows\\System32\\[a-zA-Z0-9]{8}\.tmp$'
    condition: selection
falsepositives:
    - Unknown
level: high

```