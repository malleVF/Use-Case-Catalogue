---
title: "MSSQL XPCmdshell Option Change"
status: "test"
created: "2022/07/12"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "windows"
logsrc_service: "application"
level: "high"
---

## MSSQL XPCmdshell Option Change

### Description

Detects when the MSSQL "xp_cmdshell" stored procedure setting is changed

```yml
title: MSSQL XPCmdshell Option Change
id: d08dd86f-681e-4a00-a92c-1db218754417
status: test
description: Detects when the MSSQL "xp_cmdshell" stored procedure setting is changed
references:
    - https://www.netspi.com/blog/technical/network-penetration-testing/sql-server-persistence-part-1-startup-stored-procedures/
    - https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/07/12
tags:
    - attack.execution
logsource:
    product: windows
    service: application
    # warning: The 'data' field used in the detection section is the container for the event data as a whole. You may have to adapt the rule for your backend accordingly
detection:
    selection:
        Provider_Name: 'MSSQLSERVER'
        EventID: 15457
        Data|contains: 'xp_cmdshell'
    condition: selection
falsepositives:
    - Legitimate enable/disable of the setting
    - Note that since the event contain the change for both values. This means that this will trigger on both enable and disable
level: high

```
