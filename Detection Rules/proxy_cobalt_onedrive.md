---
title: "CobaltStrike Malleable OneDrive Browsing Traffic Profile"
status: "test"
created: "2019/11/12"
last_modified: "2022/08/15"
tags: [defense_evasion, command_and_control, t1071_001, detection_rule]
logsrc_product: ""
logsrc_service: ""
level: "high"
---

## CobaltStrike Malleable OneDrive Browsing Traffic Profile

### Description

Detects Malleable OneDrive Profile

```yml
title: CobaltStrike Malleable OneDrive Browsing Traffic Profile
id: c9b33401-cc6a-4cf6-83bb-57ddcb2407fc
status: test
description: Detects Malleable OneDrive Profile
references:
    - https://github.com/rsmudge/Malleable-C2-Profiles/blob/26323784672913923d20c5a638c6ca79459e8529/normal/onedrive_getonly.profile
author: Markus Neis
date: 2019/11/12
modified: 2022/08/15
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        cs-method: 'GET'
        c-uri|endswith: '\?manifest=wac'
        cs-host: 'onedrive.live.com'
    filter:
        c-uri|startswith: 'http'
        c-uri|contains: '://onedrive.live.com/'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
