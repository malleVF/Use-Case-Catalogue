---
title: "WMI Event Consumer Created Named Pipe"
status: "test"
created: "2021/09/01"
last_modified: "2023/11/30"
tags: [t1047, execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## WMI Event Consumer Created Named Pipe

### Description

Detects the WMI Event Consumer service scrcons.exe creating a named pipe

```yml
title: WMI Event Consumer Created Named Pipe
id: 493fb4ab-cdcc-4c4f-818c-0e363bd1e4bb
status: test
description: Detects the WMI Event Consumer service scrcons.exe creating a named pipe
references:
    - https://github.com/RiccardoAncarani/LiquidSnake
author: Florian Roth (Nextron Systems)
date: 2021/09/01
modified: 2023/11/30
tags:
    - attack.t1047
    - attack.execution
logsource:
    product: windows
    category: pipe_created
    definition: 'Note that you have to configure logging for Named Pipe Events in Sysmon config (Event ID 17 and Event ID 18). The basic configuration is in popular sysmon configuration (https://github.com/SwiftOnSecurity/sysmon-config), but it is worth verifying. You can also use other repo, e.g. https://github.com/Neo23x0/sysmon-config, https://github.com/olafhartong/sysmon-modular. How to test detection? You can check powershell script from this site https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575'
detection:
    selection:
        Image|endswith: '\scrcons.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium

```