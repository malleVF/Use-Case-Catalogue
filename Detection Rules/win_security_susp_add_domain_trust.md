---
title: "Addition of Domain Trusts"
status: "stable"
created: "2019/12/03"
last_modified: ""
tags: [persistence, t1098, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Addition of Domain Trusts

### Description

Addition of domains is seldom and should be verified for legitimacy.

```yml
title: Addition of Domain Trusts
id: 0255a820-e564-4e40-af2b-6ac61160335c
status: stable
description: Addition of domains is seldom and should be verified for legitimacy.
author: Thomas Patzke
date: 2019/12/03
tags:
    - attack.persistence
    - attack.t1098
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4706
    condition: selection
falsepositives:
    - Legitimate extension of domain structure
level: medium

```
