---
title: "Restricted Software Access By SRP"
status: "test"
created: "2023/01/12"
last_modified: ""
tags: [defense_evasion, t1072, detection_rule]
logsrc_product: "windows"
logsrc_service: "application"
level: "high"
---

## Restricted Software Access By SRP

### Description

Detects restricted access to applications by the Software Restriction Policies (SRP) policy

```yml
title: Restricted Software Access By SRP
id: b4c8da4a-1c12-46b0-8a2b-0a8521d03442
status: test
description: Detects restricted access to applications by the Software Restriction Policies (SRP) policy
references:
    - https://learn.microsoft.com/en-us/windows-server/identity/software-restriction-policies/software-restriction-policies
    - https://github.com/nasbench/EVTX-ETW-Resources/blob/7a806a148b3d9d381193d4a80356016e6e8b1ee8/ETWEventsList/CSV/Windows11/22H2/W11_22H2_Pro_20220920_22621.382/Providers/Microsoft-Windows-AppXDeployment-Server.csv
author: frack113
date: 2023/01/12
tags:
    - attack.defense_evasion
    - attack.t1072
logsource:
    product: windows
    service: application
detection:
    selection:
        Provider_Name: 'Microsoft-Windows-SoftwareRestrictionPolicies'
        EventID:
            - 865 # Access to %1 has been restricted by your Administrator by the default software restriction policy level
            - 866 # Access to %1 has been restricted by your Administrator by location with policy rule %2 placed on path %3.
            - 867 # Access to %1 has been restricted by your Administrator by software publisher policy.
            - 868 # Access to %1 has been restricted by your Administrator by policy rule %2.
            - 882 # Access to %1 has been restricted by your Administrator by policy rule %2.
    condition: selection
falsepositives:
    - Unknown
level: high

```
