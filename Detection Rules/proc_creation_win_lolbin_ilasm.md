---
title: "Ilasm Lolbin Use Compile C-Sharp"
status: "test"
created: "2022/05/07"
last_modified: "2022/05/16"
tags: [defense_evasion, t1127, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Ilasm Lolbin Use Compile C-Sharp

### Description

Detect use of Ilasm.exe to compile c# code into dll or exe.

```yml
title: Ilasm Lolbin Use Compile C-Sharp
id: 850d55f9-6eeb-4492-ad69-a72338f65ba4
status: test
description: Detect use of Ilasm.exe to compile c# code into dll or exe.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Ilasm/
    - https://www.echotrail.io/insights/search/ilasm.exe
author: frack113
date: 2022/05/07
modified: 2022/05/16
tags:
    - attack.defense_evasion
    - attack.t1127
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        - Image|endswith: '\ilasm.exe'
        - OriginalFileName: 'ilasm.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
