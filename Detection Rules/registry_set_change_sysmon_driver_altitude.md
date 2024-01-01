---
title: "Disable Sysmon Event Logging Via Registry"
status: "experimental"
created: "2022/07/28"
last_modified: "2023/08/17"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Disable Sysmon Event Logging Via Registry

### Description

Detects changes in Sysmon driver altitude. If the Sysmon driver is configured to load at an altitude of another registered service, it will fail to load at boot.

```yml
title: Disable Sysmon Event Logging Via Registry
id: 4916a35e-bfc4-47d0-8e25-a003d7067061
status: experimental
description: Detects changes in Sysmon driver altitude. If the Sysmon driver is configured to load at an altitude of another registered service, it will fail to load at boot.
references:
    - https://posts.specterops.io/shhmon-silencing-sysmon-via-driver-unload-682b5be57650
    - https://youtu.be/zSihR3lTf7g
author: B.Talebi
date: 2022/07/28
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|startswith: 'HKLM\SYSTEM\CurrentControlSet\'
        TargetObject|endswith: '\Instances\Sysmon Instance\Altitude'
    condition: selection
falsepositives:
    - Legitimate driver altitude change to hide sysmon
level: high

```