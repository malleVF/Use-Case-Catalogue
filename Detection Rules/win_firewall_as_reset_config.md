---
title: "Windows Defender Firewall Has Been Reset To Its Default Configuration"
status: "experimental"
created: "2022/02/19"
last_modified: "2023/04/21"
tags: [defense_evasion, t1562_004, detection_rule]
logsrc_product: "windows"
logsrc_service: "firewall-as"
level: "low"
---

## Windows Defender Firewall Has Been Reset To Its Default Configuration

### Description

Detects activity when Windows Defender Firewall has been reset to its default configuration

```yml
title: Windows Defender Firewall Has Been Reset To Its Default Configuration
id: 04b60639-39c0-412a-9fbe-e82499c881a3
status: experimental
description: Detects activity when Windows Defender Firewall has been reset to its default configuration
references:
    - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)
author: frack113
date: 2022/02/19
modified: 2023/04/21
tags:
    - attack.defense_evasion
    - attack.t1562.004
logsource:
    product: windows
    service: firewall-as
detection:
    selection:
        EventID:
            - 2032 # Windows Defender Firewall has been reset to its default configuration
            - 2060 # Windows Defender Firewall has been reset to its default configuration. (Windows 11)
    condition: selection
level: low

```
