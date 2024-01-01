---
title: "PUA - CSExec Default Named Pipe"
status: "test"
created: "2023/08/07"
last_modified: "2023/11/30"
tags: [lateral_movement, t1021_002, execution, t1569_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PUA - CSExec Default Named Pipe

### Description

Detects default CSExec pipe creation

```yml
title: PUA - CSExec Default Named Pipe
id: f318b911-ea88-43f4-9281-0de23ede628e
related:
    - id: 9e77ed63-2ecf-4c7b-b09d-640834882028
      type: obsoletes
status: test
description: Detects default CSExec pipe creation
references:
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
    - https://github.com/malcomvetter/CSExec
author: Nikita Nazarov, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2023/08/07
modified: 2023/11/30
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.execution
    - attack.t1569.002
logsource:
    product: windows
    category: pipe_created
    definition: 'Note that you have to configure logging for Named Pipe Events in Sysmon config (Event ID 17 and Event ID 18). The basic configuration is in popular sysmon configuration (https://github.com/SwiftOnSecurity/sysmon-config), but it is worth verifying. You can also use other repo, e.g. https://github.com/Neo23x0/sysmon-config, https://github.com/olafhartong/sysmon-modular. How to test detection? You can check powershell script from this site https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575'
detection:
    selection:
        PipeName|contains: '\csexecsvc'
    condition: selection
falsepositives:
    - Legitimate Administrator activity
level: medium

```