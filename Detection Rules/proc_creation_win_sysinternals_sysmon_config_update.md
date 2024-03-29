---
title: "Sysmon Configuration Update"
status: "test"
created: "2023/03/09"
last_modified: ""
tags: [defense_evasion, t1562_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Sysmon Configuration Update

### Description

Detects updates to Sysmon's configuration. Attackers might update or replace the Sysmon configuration with a bare bone one to avoid monitoring without shutting down the service completely

```yml
title: Sysmon Configuration Update
id: 87911521-7098-470b-a459-9a57fc80bdfd
status: test
description: Detects updates to Sysmon's configuration. Attackers might update or replace the Sysmon configuration with a bare bone one to avoid monitoring without shutting down the service completely
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/03/09
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_pe:
        - Image|endswith:
              - \Sysmon64.exe
              - \Sysmon.exe
        - Description: 'System activity monitor'
    selection_cli:
        CommandLine|contains:
            - '-c'
            - '/c'
    condition: all of selection_*
falsepositives:
    - Legitimate administrators might use this command to update Sysmon configuration.
level: medium

```
