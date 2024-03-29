---
title: "New or Renamed User Account with '$' in Attribute 'SamAccountName'"
status: "test"
created: "2019/10/25"
last_modified: "2022/11/22"
tags: [defense_evasion, t1036, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## New or Renamed User Account with '$' in Attribute 'SamAccountName'

### Description

Detects possible bypass EDR and SIEM via abnormal user account name.

```yml
title: New or Renamed User Account with '$' in Attribute 'SamAccountName'
id: cfeed607-6aa4-4bbd-9627-b637deb723c8
status: test
description: Detects possible bypass EDR and SIEM via abnormal user account name.
author: Ilyas Ochkov, oscd.community
date: 2019/10/25
modified: 2022/11/22
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4720 # create user
        SamAccountName|contains: '$'
    selection2:
        EventID: 4781 # rename user
        NewTargetUserName|contains: '$'
    condition: 1 of selection*
fields:
    - EventID
    - SamAccountName
    - SubjectUserName
    - NewTargetUserName
falsepositives:
    - Unknown
level: high

```
