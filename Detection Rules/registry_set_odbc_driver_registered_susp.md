---
title: "Potentially Suspicious ODBC Driver Registered"
status: "experimental"
created: "2023/05/23"
last_modified: "2023/08/17"
tags: [persistence, t1003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potentially Suspicious ODBC Driver Registered

### Description

Detects the registration of a new ODBC driver where the driver is located in a potentially suspicious location

```yml
title: Potentially Suspicious ODBC Driver Registered
id: e4d22291-f3d5-4b78-9a0c-a1fbaf32a6a4
status: experimental
description: Detects the registration of a new ODBC driver where the driver is located in a potentially suspicious location
references:
    - https://www.hexacorn.com/blog/2020/08/23/odbcconf-lolbin-trifecta/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/23
modified: 2023/08/17
tags:
    - attack.persistence
    - attack.t1003
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\SOFTWARE\ODBC\ODBCINST.INI\'
        TargetObject|endswith:
            - '\Driver'
            - '\Setup'
        Details|contains:
            - ':\PerfLogs\'
            - ':\ProgramData\'
            - ':\Temp\'
            - ':\Users\Public\'
            - ':\Windows\Registration\CRMLog'
            - ':\Windows\System32\com\dmp\'
            - ':\Windows\System32\FxsTmp\'
            - ':\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\'
            - ':\Windows\System32\spool\drivers\color\'
            - ':\Windows\System32\spool\PRINTERS\'
            - ':\Windows\System32\spool\SERVERS\'
            - ':\Windows\System32\Tasks_Migrated\'
            - ':\Windows\System32\Tasks\Microsoft\Windows\SyncCenter\'
            - ':\Windows\SysWOW64\com\dmp\'
            - ':\Windows\SysWOW64\FxsTmp\'
            - ':\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System\'
            - ':\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\'
            - ':\Windows\Tasks\'
            - ':\Windows\Temp\'
            - ':\Windows\Tracing\'
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\'
    condition: selection
falsepositives:
    - Unlikely
level: high

```