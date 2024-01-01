---
title: "Windows Defender Exclusions Added"
status: "stable"
created: "2021/07/06"
last_modified: "2022/12/06"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "windefend"
level: "medium"
---

## Windows Defender Exclusions Added

### Description

Detects the Setting of Windows Defender Exclusions

```yml
title: Windows Defender Exclusions Added
id: 1321dc4e-a1fe-481d-a016-52c45f0c8b4f
status: stable
description: Detects the Setting of Windows Defender Exclusions
references:
    - https://twitter.com/_nullbind/status/1204923340810543109
author: Christian Burkard (Nextron Systems)
date: 2021/07/06
modified: 2022/12/06
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID: 5007 # The antimalware platform configuration changed.
        NewValue|contains: '\Microsoft\Windows Defender\Exclusions'
    condition: selection
falsepositives:
    - Administrator actions
level: medium

```
