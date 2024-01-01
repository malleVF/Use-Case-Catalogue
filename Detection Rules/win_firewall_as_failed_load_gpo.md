---
title: "The Windows Defender Firewall Service Failed To Load Group Policy"
status: "test"
created: "2022/02/19"
last_modified: "2023/01/17"
tags: [defense_evasion, t1562_004, detection_rule]
logsrc_product: "windows"
logsrc_service: "firewall-as"
level: "low"
---

## The Windows Defender Firewall Service Failed To Load Group Policy

### Description

Detects activity when The Windows Defender Firewall service failed to load Group Policy

```yml
title: The Windows Defender Firewall Service Failed To Load Group Policy
id: 7ec15688-fd24-4177-ba43-1a950537ee39
status: test
description: Detects activity when The Windows Defender Firewall service failed to load Group Policy
references:
    - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)
author: frack113
date: 2022/02/19
modified: 2023/01/17
tags:
    - attack.defense_evasion
    - attack.t1562.004
logsource:
    product: windows
    service: firewall-as
detection:
    selection:
        EventID: 2009 # The Windows Defender Firewall service failed to load Group Policy
    condition: selection
level: low

```
