---
title: "Password Change on Directory Service Restore Mode (DSRM) Account"
status: "stable"
created: "2017/02/19"
last_modified: "2020/08/23"
tags: [persistence, t1098, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "high"
---

## Password Change on Directory Service Restore Mode (DSRM) Account

### Description

The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.

```yml
title: Password Change on Directory Service Restore Mode (DSRM) Account
id: 53ad8e36-f573-46bf-97e4-15ba5bf4bb51
status: stable
description: The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.
references:
    - https://adsecurity.org/?p=1714
author: Thomas Patzke
date: 2017/02/19
modified: 2020/08/23
tags:
    - attack.persistence
    - attack.t1098
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4794
    condition: selection
falsepositives:
    - Initial installation of a domain controller
level: high

```
