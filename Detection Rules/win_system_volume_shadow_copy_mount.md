---
title: "Volume Shadow Copy Mount"
status: "test"
created: "2020/10/20"
last_modified: "2022/12/25"
tags: [credential_access, t1003_002, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "low"
---

## Volume Shadow Copy Mount

### Description

Detects volume shadow copy mount via Windows event log

```yml
title: Volume Shadow Copy Mount
id: f512acbf-e662-4903-843e-97ce4652b740
status: test
description: Detects volume shadow copy mount via Windows event log
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy
author: Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR)
date: 2020/10/20
modified: 2022/12/25
tags:
    - attack.credential_access
    - attack.t1003.002
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: Microsoft-Windows-Ntfs
        EventID: 98
        DeviceName|contains: HarddiskVolumeShadowCopy
    condition: selection
falsepositives:
    - Legitimate use of volume shadow copy mounts (backups maybe).
level: low

```
