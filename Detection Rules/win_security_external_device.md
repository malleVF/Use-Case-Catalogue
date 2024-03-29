---
title: "External Disk Drive Or USB Storage Device"
status: "test"
created: "2019/11/20"
last_modified: "2022/10/09"
tags: [t1091, t1200, lateral_movement, initial_access, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "low"
---

## External Disk Drive Or USB Storage Device

### Description

Detects external diskdrives or plugged in USB devices, EventID 6416 on Windows 10 or later

```yml
title: External Disk Drive Or USB Storage Device
id: f69a87ea-955e-4fb4-adb2-bb9fd6685632
status: test
description: Detects external diskdrives or plugged in USB devices, EventID 6416 on Windows 10 or later
author: Keith Wright
date: 2019/11/20
modified: 2022/10/09
tags:
    - attack.t1091
    - attack.t1200
    - attack.lateral_movement
    - attack.initial_access
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 6416
        ClassName: 'DiskDrive'
    selection2:
        DeviceDescription: 'USB Mass Storage Device'
    condition: selection or selection2
falsepositives:
    - Legitimate administrative activity
level: low

```
