---
title: "Potential Credential Dumping Via WER - Application"
status: "test"
created: "2022/12/07"
last_modified: ""
tags: [credential_access, t1003_001, detection_rule]
logsrc_product: "windows"
logsrc_service: "application"
level: "high"
---

## Potential Credential Dumping Via WER - Application

### Description

Detects Windows error reporting event where the process that crashed is lsass. This could be the cause of an intentional crash by techniques such as Lsass-Shtinkering to dump credential

```yml
title: Potential Credential Dumping Via WER - Application
id: a18e0862-127b-43ca-be12-1a542c75c7c5
status: test
description: Detects Windows error reporting event where the process that crashed is lsass. This could be the cause of an intentional crash by techniques such as Lsass-Shtinkering to dump credential
references:
    - https://github.com/deepinstinct/Lsass-Shtinkering
    - https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/12/07
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    product: windows
    service: application
detection:
    selection:
        Provider_Name: 'Application Error'
        EventID: 1000
        AppName: 'lsass.exe'
        ExceptionCode: 'c0000001' # STATUS_UNSUCCESSFUL
    condition: selection
falsepositives:
    - Rare legitimate crashing of the lsass process
level: high

```
