---
title: "Potential SAM Database Dump"
status: "test"
created: "2022/02/11"
last_modified: "2023/01/05"
tags: [credential_access, t1003_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential SAM Database Dump

### Description

Detects the creation of files that look like exports of the local SAM (Security Account Manager)

```yml
title: Potential SAM Database Dump
id: 4e87b8e2-2ee9-4b2a-a715-4727d297ece0
status: test
description: Detects the creation of files that look like exports of the local SAM (Security Account Manager)
references:
    - https://github.com/search?q=CVE-2021-36934
    - https://github.com/cube0x0/CVE-2021-36934
    - https://www.google.com/search?q=%22reg.exe+save%22+sam
    - https://github.com/HuskyHacks/ShadowSteal
    - https://github.com/FireFart/hivenightmare
author: Florian Roth (Nextron Systems)
date: 2022/02/11
modified: 2023/01/05
tags:
    - attack.credential_access
    - attack.t1003.002
logsource:
    product: windows
    category: file_event
detection:
    selection:
        - TargetFilename|endswith:
              - '\Temp\sam'
              - '\sam.sav'
              - '\Intel\sam'
              - '\sam.hive'
              - '\Perflogs\sam'
              - '\ProgramData\sam'
              - '\Users\Public\sam'
              - '\AppData\Local\sam'
              - '\AppData\Roaming\sam'
              - '_ShadowSteal.zip'       # https://github.com/HuskyHacks/ShadowSteal
              - '\Documents\SAM.export'  # https://github.com/n3tsurge/CVE-2021-36934/
              - ':\sam'
        - TargetFilename|contains:
              - '\hive_sam_'             # https://github.com/FireFart/hivenightmare
              - '\sam.save'
              - '\sam.export'
              - '\~reg_sam.save'
              - '\sam_backup'
              - '\sam.bck'
              - '\sam.backup'
    condition: selection
falsepositives:
    - Rare cases of administrative activity
level: high

```