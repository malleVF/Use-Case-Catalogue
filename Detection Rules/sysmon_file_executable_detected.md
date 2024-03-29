---
title: "Sysmon File Executable Creation Detected"
status: "experimental"
created: "2023/07/20"
last_modified: ""
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: "sysmon"
level: "medium"
---

## Sysmon File Executable Creation Detected

### Description

Triggers on any Sysmon "FileExecutableDetected" event, which triggers every time a PE that is monitored by the config is created.

```yml
title: Sysmon File Executable Creation Detected
id: 693a44e9-7f26-4cb6-b787-214867672d3a
status: experimental
description: Triggers on any Sysmon "FileExecutableDetected" event, which triggers every time a PE that is monitored by the config is created.
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    - https://medium.com/@olafhartong/sysmon-15-0-file-executable-detected-40fd64349f36
author: frack113
date: 2023/07/20
tags:
    - attack.defense_evasion
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 29  # this is fine, we want to match any FileExecutableDetected event
    condition: selection
falsepositives:
    - Unlikely
level: medium

```
