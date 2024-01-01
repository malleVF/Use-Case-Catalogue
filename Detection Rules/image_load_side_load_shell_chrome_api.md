---
title: "DLL Sideloading Of ShellChromeAPI.DLL"
status: "test"
created: "2022/12/01"
last_modified: ""
tags: [defense_evasion, persistence, privilege_escalation, t1574_001, t1574_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## DLL Sideloading Of ShellChromeAPI.DLL

### Description

Detects processes loading the non-existent DLL "ShellChromeAPI". One known example is the "DeviceEnroller" binary in combination with the "PhoneDeepLink" flag tries to load this DLL.
Adversaries can drop their own renamed DLL and execute it via DeviceEnroller.exe using this parameter


```yml
title: DLL Sideloading Of ShellChromeAPI.DLL
id: ee4c5d06-3abc-48cc-8885-77f1c20f4451
related:
    - id: e173ad47-4388-4012-ae62-bd13f71c18a8
      type: similar
status: test
description: |
    Detects processes loading the non-existent DLL "ShellChromeAPI". One known example is the "DeviceEnroller" binary in combination with the "PhoneDeepLink" flag tries to load this DLL.
    Adversaries can drop their own renamed DLL and execute it via DeviceEnroller.exe using this parameter
references:
    - https://mobile.twitter.com/0gtweet/status/1564131230941122561
    - https://strontic.github.io/xcyclopedia/library/DeviceEnroller.exe-24BEF0D6B0ECED36BB41831759FDE18D.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/12/01
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1574.001
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        # The DLL shouldn't exist on Windows anymore. If for some reason you still have it. You could filter out legitimate calls
        ImageLoaded|endswith: '\ShellChromeAPI.dll'
    condition: selection
falsepositives:
    - Unknown
level: high

```
