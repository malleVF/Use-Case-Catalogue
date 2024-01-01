---
title: "Win Defender Restored Quarantine File"
status: "test"
created: "2022/12/06"
last_modified: ""
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "windefend"
level: "high"
---

## Win Defender Restored Quarantine File

### Description

Detects the restoration of files from the defender quarantine

```yml
title: Win Defender Restored Quarantine File
id: bc92ca75-cd42-4d61-9a37-9d5aa259c88b
status: test
description: Detects the restoration of files from the defender quarantine
references:
    - https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/12/06
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID: 1009 # The antimalware platform restored an item from quarantine.
    condition: selection
falsepositives:
    - Legitimate administrator activity restoring a file
level: high

```