---
title: "CobaltStrike Malleable (OCSP) Profile"
status: "test"
created: "2019/11/12"
last_modified: "2021/11/27"
tags: [defense_evasion, command_and_control, t1071_001, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## CobaltStrike Malleable (OCSP) Profile

### Description

Detects Malleable (OCSP) Profile with Typo (OSCP) in URL

```yml
title: CobaltStrike Malleable (OCSP) Profile
id: 37325383-740a-403d-b1a2-b2b4ab7992e7
status: test
description: Detects Malleable (OCSP) Profile with Typo (OSCP) in URL
references:
    - https://github.com/rsmudge/Malleable-C2-Profiles/blob/26323784672913923d20c5a638c6ca79459e8529/normal/ocsp.profile
author: Markus Neis
date: 2019/11/12
modified: 2021/11/27
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '/oscp/'
        cs-host: 'ocsp.verisign.com'
    condition: selection
falsepositives:
    - Unknown
level: high

```
