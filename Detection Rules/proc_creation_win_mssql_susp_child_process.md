---
title: "Suspicious Child Process Of SQL Server"
status: "experimental"
created: "2020/12/11"
last_modified: "2023/05/04"
tags: [t1505_003, t1190, initial_access, persistence, privilege_escalation, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Child Process Of SQL Server

### Description

Detects suspicious child processes of the SQLServer process. This could indicate potential RCE or SQL Injection.

```yml
title: Suspicious Child Process Of SQL Server
id: 869b9ca7-9ea2-4a5a-8325-e80e62f75445
related:
    - id: 344482e4-a477-436c-aa70-7536d18a48c7
      type: obsoletes
status: experimental
description: Detects suspicious child processes of the SQLServer process. This could indicate potential RCE or SQL Injection.
author: FPT.EagleEye Team, wagga
date: 2020/12/11
modified: 2023/05/04
tags:
    - attack.t1505.003
    - attack.t1190
    - attack.initial_access
    - attack.persistence
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\sqlservr.exe'
        Image|endswith:
            # You can add other uncommon or suspicious processes
            - '\bash.exe'
            - '\bitsadmin.exe'
            - '\cmd.exe'
            - '\netstat.exe'
            - '\nltest.exe'
            - '\ping.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\sh.exe'
            - '\systeminfo.exe'
            - '\tasklist.exe'
            - '\wsl.exe'
    filter_optional_datev:
        ParentImage|startswith: 'C:\Program Files\Microsoft SQL Server\'
        ParentImage|endswith: 'DATEV_DBENGINE\MSSQL\Binn\sqlservr.exe'
        Image: 'C:\Windows\System32\cmd.exe'
        CommandLine|startswith: '"C:\Windows\system32\cmd.exe" '
    condition: selection and not 1 of filter_optional_*
level: high

```
