---
title: "Remote PowerShell Session (Network)"
status: "test"
created: "2019/09/12"
last_modified: "2023/01/09"
tags: [execution, t1059_001, lateral_movement, t1021_006, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Remote PowerShell Session (Network)

### Description

Detects remote PowerShell connections by monitoring network outbound connections to ports 5985 or 5986 from a non-network service account.

```yml
title: Remote PowerShell Session (Network)
id: c539afac-c12a-46ed-b1bd-5a5567c9f045
status: test
description: Detects remote PowerShell connections by monitoring network outbound connections to ports 5985 or 5986 from a non-network service account.
references:
    - https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g
date: 2019/09/12
modified: 2023/01/09
tags:
    - attack.execution
    - attack.t1059.001
    - attack.lateral_movement
    - attack.t1021.006
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort:
            - 5985
            - 5986
        Initiated: 'true' # only matches of the initiating system can be evaluated
    filter_generic:
        - User|contains: # covers many language settings for Network Service. Please expand
              - 'NETWORK SERVICE'
              - 'NETZWERKDIENST'
              - 'SERVIZIO DI RETE'
              - 'SERVICIO DE RED'
        - User|contains|all:
              - 'SERVICE R'
              - 'SEAU'
        - SourceIp|startswith: '0:0:'
        - Image:
              - 'C:\Program Files\Avast Software\Avast\AvastSvc.exe'
              - 'C:\Program Files (x86)\Avast Software\Avast\AvastSvc.exe'
    filter_localhost:
        SourceIp:
            - '::1'
            - '127.0.0.1'
        DestinationIp:
            - '::1'
            - '127.0.0.1'
    condition: selection and not 1 of filter_*
falsepositives:
    - Legitimate usage of remote PowerShell, e.g. remote administration and monitoring.
    - Network Service user name of a not-covered localization
level: high

```
