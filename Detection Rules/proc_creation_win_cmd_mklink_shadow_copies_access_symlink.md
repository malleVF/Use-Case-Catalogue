---
title: "VolumeShadowCopy Symlink Creation Via Mklink"
status: "stable"
created: "2019/10/22"
last_modified: "2023/03/06"
tags: [credential_access, t1003_002, t1003_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## VolumeShadowCopy Symlink Creation Via Mklink

### Description

Shadow Copies storage symbolic link creation using operating systems utilities

```yml
title: VolumeShadowCopy Symlink Creation Via Mklink
id: 40b19fa6-d835-400c-b301-41f3a2baacaf
status: stable
description: Shadow Copies storage symbolic link creation using operating systems utilities
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
author: Teymur Kheirkhabarov, oscd.community
date: 2019/10/22
modified: 2023/03/06
tags:
    - attack.credential_access
    - attack.t1003.002
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'mklink'
            - 'HarddiskVolumeShadowCopy'
    condition: selection
falsepositives:
    - Legitimate administrator working with shadow copies, access for backup purposes
level: high

```
