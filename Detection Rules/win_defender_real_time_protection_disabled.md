---
title: "Windows Defender Real-time Protection Disabled"
status: "stable"
created: "2020/07/28"
last_modified: "2023/11/22"
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "windefend"
level: "high"
---

## Windows Defender Real-time Protection Disabled

### Description

Detects disabling of Windows Defender Real-time Protection. As this event doesn't contain a lot of information on who initaited this action you might want to reduce it to a "medium" level if this occurs too many times in your environment


```yml
title: Windows Defender Real-time Protection Disabled
id: b28e58e4-2a72-4fae-bdee-0fbe904db642
related:
    - id: fe34868f-6e0e-4882-81f6-c43aa8f15b62
      type: obsoletes
status: stable
description: |
    Detects disabling of Windows Defender Real-time Protection. As this event doesn't contain a lot of information on who initaited this action you might want to reduce it to a "medium" level if this occurs too many times in your environment
references:
    - https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide#event-id-5001
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
    - https://craigclouditpro.wordpress.com/2020/03/04/hunting-malicious-windows-defender-activity/
author: Ján Trenčanský, frack113
date: 2020/07/28
modified: 2023/11/22
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID: 5001 # Real-time protection is disabled.
    condition: selection
falsepositives:
    - Administrator actions (should be investigated)
    - Seen being triggered occasionally during Windows 8 Defender Updates
level: high

```