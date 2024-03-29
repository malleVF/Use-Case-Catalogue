---
title: "PUA - Sysinternals Tools Execution - Registry"
status: "experimental"
created: "2022/08/24"
last_modified: "2023/02/07"
tags: [resource_development, t1588_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PUA - Sysinternals Tools Execution - Registry

### Description

Detects the execution of some potentially unwanted tools such as PsExec, Procdump, etc. (part of the Sysinternals suite) via the creation of the "accepteula" registry key.

```yml
title: PUA - Sysinternals Tools Execution - Registry
id: c7da8edc-49ae-45a2-9e61-9fd860e4e73d
related:
    - id: 25ffa65d-76d8-4da5-a832-3f2b0136e133
      type: derived
    - id: 9841b233-8df8-4ad7-9133-b0b4402a9014
      type: obsoletes
status: experimental
description: Detects the execution of some potentially unwanted tools such as PsExec, Procdump, etc. (part of the Sysinternals suite) via the creation of the "accepteula" registry key.
references:
    - https://twitter.com/Moti_B/status/1008587936735035392
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/24
modified: 2023/02/07
tags:
    - attack.resource_development
    - attack.t1588.002
logsource:
    product: windows
    category: registry_add
detection:
    selection:
        EventType: CreateKey
        TargetObject|contains:
            - '\Active Directory Explorer'
            - '\Handle'
            - '\LiveKd'
            - '\Process Explorer'
            - '\ProcDump'
            - '\PsExec'
            - '\PsLoglist'
            - '\PsPasswd'
            - '\SDelete'
            - '\Sysinternals' # Global level https://twitter.com/leonzandman/status/1561736801953382400
        TargetObject|endswith: '\EulaAccepted'
    condition: selection
falsepositives:
    - Legitimate use of SysInternals tools. Filter the legitimate paths used in your environment
level: medium

```
