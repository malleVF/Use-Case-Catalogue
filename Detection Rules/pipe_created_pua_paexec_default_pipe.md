---
title: "PUA - PAExec Default Named Pipe"
status: "test"
created: "2022/10/26"
last_modified: ""
tags: [execution, t1569_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PUA - PAExec Default Named Pipe

### Description

Detects PAExec default named pipe

```yml
title: PUA - PAExec Default Named Pipe
id: f6451de4-df0a-41fa-8d72-b39f54a08db5
status: test
description: Detects PAExec default named pipe
references:
    - https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/efa17a600b43c897b4b7463cc8541daa1987eeb4/Command%20and%20Control/C2-NamedPipe.md
    - https://github.com/poweradminllc/PAExec
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/10/26
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    category: pipe_created
    product: windows
    definition: 'Note that you have to configure logging for Named Pipe Events in Sysmon config (Event ID 17 and Event ID 18). The basic configuration is in popular sysmon configuration (https://github.com/SwiftOnSecurity/sysmon-config), but it is worth verifying. You can also use other repo, e.g. https://github.com/Neo23x0/sysmon-config, https://github.com/olafhartong/sysmon-modular. How to test detection? You can check powershell script from this site https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575'
detection:
    selection:
        PipeName|startswith: '\PAExec'
    condition: selection
falsepositives:
    - Unknown
level: medium

```
