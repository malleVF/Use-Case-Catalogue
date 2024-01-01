---
title: "Lolbin Defaultpack.exe Use As Proxy"
status: "test"
created: "2022/12/31"
last_modified: ""
tags: [t1218, defense_evasion, execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Lolbin Defaultpack.exe Use As Proxy

### Description

Detect usage of the "defaultpack.exe" binary as a proxy to launch other programs

```yml
title: Lolbin Defaultpack.exe Use As Proxy
id: b2309017-4235-44fe-b5af-b15363011957
status: test
description: Detect usage of the "defaultpack.exe" binary as a proxy to launch other programs
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/DefaultPack/
    - https://www.echotrail.io/insights/search/defaultpack.exe
author: frack113
date: 2022/12/31
tags:
    - attack.t1218
    - attack.defense_evasion
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\defaultpack.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
