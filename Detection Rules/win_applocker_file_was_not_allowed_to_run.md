---
title: "File Was Not Allowed To Run"
status: "test"
created: "2020/06/28"
last_modified: "2021/11/27"
tags: [execution, t1204_002, t1059_001, t1059_003, t1059_005, t1059_006, t1059_007, detection_rule]
logsrc_product: "windows"
logsrc_service: "applocker"
level: "medium"
---

## File Was Not Allowed To Run

### Description

Detect run not allowed files. Applocker is a very useful tool, especially on servers where unprivileged users have access. For example terminal servers. You need configure applocker and log collect to receive these events.

```yml
title: File Was Not Allowed To Run
id: 401e5d00-b944-11ea-8f9a-00163ecd60ae
status: test
description: Detect run not allowed files. Applocker is a very useful tool, especially on servers where unprivileged users have access. For example terminal servers. You need configure applocker and log collect to receive these events.
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/using-event-viewer-with-applocker
    - https://nxlog.co/documentation/nxlog-user-guide/applocker.html
author: Pushkarev Dmitry
date: 2020/06/28
modified: 2021/11/27
tags:
    - attack.execution
    - attack.t1204.002
    - attack.t1059.001
    - attack.t1059.003
    - attack.t1059.005
    - attack.t1059.006
    - attack.t1059.007
logsource:
    product: windows
    service: applocker
detection:
    selection:
        EventID:
            - 8004
            - 8007
            - 8022
            - 8025
    condition: selection
fields:
    - PolicyName
    - RuleId
    - RuleName
    - TargetUser
    - TargetProcessId
    - FilePath
    - FileHash
    - Fqbn
falsepositives:
    - Need tuning applocker or add exceptions in SIEM
level: medium

```
