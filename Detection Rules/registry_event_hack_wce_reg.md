---
title: "Windows Credential Editor Registry"
status: "test"
created: "2019/12/31"
last_modified: "2021/11/27"
tags: [credential_access, t1003_001, s0005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "critical"
---

## Windows Credential Editor Registry

### Description

Detects the use of Windows Credential Editor (WCE)

```yml
title: Windows Credential Editor Registry
id: a6b33c02-8305-488f-8585-03cb2a7763f2
status: test
description: Detects the use of Windows Credential Editor (WCE)
references:
    - https://www.ampliasecurity.com/research/windows-credentials-editor/
author: Florian Roth (Nextron Systems)
date: 2019/12/31
modified: 2021/11/27
tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.s0005
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains: Services\WCESERVICE\Start
    condition: selection
falsepositives:
    - Unknown
level: critical

```
