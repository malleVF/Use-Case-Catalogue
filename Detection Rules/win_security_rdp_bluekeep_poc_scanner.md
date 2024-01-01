---
title: "Scanner PoC for CVE-2019-0708 RDP RCE Vuln"
status: "test"
created: "2019/06/02"
last_modified: "2022/12/25"
tags: [lateral_movement, t1210, car_2013-07-002, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Scanner PoC for CVE-2019-0708 RDP RCE Vuln

### Description

Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep

```yml
title: Scanner PoC for CVE-2019-0708 RDP RCE Vuln
id: 8400629e-79a9-4737-b387-5db940ab2367
status: test
description: Detects the use of a scanner by zerosum0x0 that discovers targets vulnerable to  CVE-2019-0708 RDP RCE aka BlueKeep
references:
    - https://twitter.com/AdamTheAnalyst/status/1134394070045003776
    - https://github.com/zerosum0x0/CVE-2019-0708
author: Florian Roth (Nextron Systems), Adam Bradbury (idea)
date: 2019/06/02
modified: 2022/12/25
tags:
    - attack.lateral_movement
    - attack.t1210
    - car.2013-07-002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
        TargetUserName: AAAAAAA
    condition: selection
falsepositives:
    - Unlikely
level: high

```
