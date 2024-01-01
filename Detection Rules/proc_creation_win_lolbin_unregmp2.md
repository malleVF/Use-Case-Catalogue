---
title: "Lolbin Unregmp2.exe Use As Proxy"
status: "test"
created: "2022/12/29"
last_modified: ""
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Lolbin Unregmp2.exe Use As Proxy

### Description

Detect usage of the "unregmp2.exe" binary as a proxy to launch a custom version of "wmpnscfg.exe"

```yml
title: Lolbin Unregmp2.exe Use As Proxy
id: 727454c0-d851-48b0-8b89-385611ab0704
status: test
description: Detect usage of the "unregmp2.exe" binary as a proxy to launch a custom version of "wmpnscfg.exe"
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Unregmp2/
author: frack113
date: 2022/12/29
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\unregmp2.exe'
        - OriginalFileName: 'unregmp2.exe'
    selection_cmd:
        CommandLine|contains: ' /HideWMP'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```