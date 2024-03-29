---
title: "Sysmon Blocked File Shredding"
status: "experimental"
created: "2023/07/20"
last_modified: ""
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: "sysmon"
level: "high"
---

## Sysmon Blocked File Shredding

### Description

Triggers on any Sysmon "FileBlockShredding" event, which indicates a violation of the configured shredding policy.

```yml
title: Sysmon Blocked File Shredding
id: c3e5c1b1-45e9-4632-b242-27939c170239
status: experimental
description: Triggers on any Sysmon "FileBlockShredding" event, which indicates a violation of the configured shredding policy.
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
author: frack113
date: 2023/07/20
tags:
    - attack.defense_evasion
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 28  # this is fine, we want to match any FileBlockShredding event
    condition: selection
falsepositives:
    - Unlikely
level: high

```
