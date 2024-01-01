---
title: "RTCore Suspicious Service Installation"
status: "test"
created: "2022/08/30"
last_modified: ""
tags: [persistence, detection_rule]
logsrc_product: "windows"
logsrc_service: "system"
level: "high"
---

## RTCore Suspicious Service Installation

### Description

Detects the installation of RTCore service. Which could be an indication of Micro-Star MSI Afterburner vulnerable driver abuse

```yml
title: RTCore Suspicious Service Installation
id: 91c49341-e2ef-40c0-ac45-49ec5c3fe26c
status: test
description: Detects the installation of RTCore service. Which could be an indication of Micro-Star MSI Afterburner vulnerable driver abuse
references:
    - https://github.com/br-sn/CheekyBlinder/blob/e1764a8a0e7cda8a3716aefa35799f560686e01c/CheekyBlinder/CheekyBlinder.cpp
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/08/30
tags:
    - attack.persistence
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ServiceName: 'RTCore64'
    condition: selection
falsepositives:
    - Unknown
level: high

```
