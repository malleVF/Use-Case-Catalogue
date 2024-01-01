---
title: "KrbRelayUp Service Installation"
status: "test"
created: "2022/05/11"
last_modified: "2022/10/05"
tags: [privilege_escalation, t1543, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "high"
---

## KrbRelayUp Service Installation

### Description

Detects service creation from KrbRelayUp tool used for privilege escalation in Windows domain environments where LDAP signing is not enforced (the default settings)

```yml
title: KrbRelayUp Service Installation
id: e97d9903-53b2-41fc-8cb9-889ed4093e80
status: test
description: Detects service creation from KrbRelayUp tool used for privilege escalation in Windows domain environments where LDAP signing is not enforced (the default settings)
references:
    - https://github.com/Dec0ne/KrbRelayUp
author: Sittikorn S, Tim Shelton
date: 2022/05/11
modified: 2022/10/05
tags:
    - attack.privilege_escalation
    - attack.t1543
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName: 'KrbSCM'
    condition: selection
falsepositives:
    - Unknown
level: high

```
