---
title: "Sudo Privilege Escalation CVE-2019-14287"
status: "test"
created: "2019/10/15"
last_modified: "2022/10/05"
tags: [privilege_escalation, t1068, t1548_003, cve_2019_14287, detection_rule]
logsrc_product: "linux"
logsrc_service: ""
level: "high"
---

## Sudo Privilege Escalation CVE-2019-14287

### Description

Detects users trying to exploit sudo vulnerability reported in CVE-2019-14287

```yml
title: Sudo Privilege Escalation CVE-2019-14287
id: f74107df-b6c6-4e80-bf00-4170b658162b
status: test
description: Detects users trying to exploit sudo vulnerability reported in CVE-2019-14287
references:
    - https://www.openwall.com/lists/oss-security/2019/10/14/1
    - https://access.redhat.com/security/cve/cve-2019-14287
    - https://twitter.com/matthieugarin/status/1183970598210412546
author: Florian Roth (Nextron Systems)
date: 2019/10/15
modified: 2022/10/05
tags:
    - attack.privilege_escalation
    - attack.t1068
    - attack.t1548.003
    - cve.2019.14287
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains: ' -u#'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
