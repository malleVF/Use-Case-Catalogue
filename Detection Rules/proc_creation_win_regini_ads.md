---
title: "Suspicious Registry Modification From ADS Via Regini.EXE"
status: "experimental"
created: "2020/10/12"
last_modified: "2023/02/08"
tags: [t1112, defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Registry Modification From ADS Via Regini.EXE

### Description

Detects the import of an alternate data stream with regini.exe, regini.exe can be used to modify registry keys.

```yml
title: Suspicious Registry Modification From ADS Via Regini.EXE
id: 77946e79-97f1-45a2-84b4-f37b5c0d8682
related:
    - id: 5f60740a-f57b-4e76-82a1-15b6ff2cb134
      type: derived
status: experimental
description: Detects the import of an alternate data stream with regini.exe, regini.exe can be used to modify registry keys.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Regini/
    - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regini
author: Eli Salem, Sander Wiebing, oscd.community
date: 2020/10/12
modified: 2023/02/08
tags:
    - attack.t1112
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\regini.exe'
        - OriginalFileName: 'REGINI.EXE'
    selection_re:
        CommandLine|re: ':[^ \\]'
    condition: all of selection_*
fields:
    - ParentImage
    - CommandLine
falsepositives:
    - Unknown
level: high

```
