---
title: "Suspicious Service Path Modification"
status: "test"
created: "2019/10/21"
last_modified: "2022/11/18"
tags: [persistence, privilege_escalation, t1543_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Service Path Modification

### Description

Detects service path modification via the "sc" binary to a suspicious command or path

```yml
title: Suspicious Service Path Modification
id: 138d3531-8793-4f50-a2cd-f291b2863d78
status: test
description: Detects service path modification via the "sc" binary to a suspicious command or path
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md
    - https://web.archive.org/web/20180331144337/https://www.fireeye.com/blog/threat-research/2018/03/sanny-malware-delivery-method-updated-in-recently-observed-attacks.html
author: Victor Sergeev, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2019/10/21
modified: 2022/11/18
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sc.exe'
        CommandLine|contains|all:
            - 'config'
            - 'binPath'
        CommandLine|contains:
            # Add more suspicious commands or binaries
            - 'powershell'
            - 'cmd '
            - 'mshta'
            - 'wscript'
            - 'cscript'
            - 'rundll32'
            - 'svchost'
            - 'dllhost'
            - 'cmd.exe /c'
            - 'cmd.exe /k'
            - 'cmd.exe /r'
            - 'cmd /c'
            - 'cmd /k'
            - 'cmd /r'
            # Add more suspicious paths
            - 'C:\Users\Public'
            - '\Downloads\'
            - '\Desktop\'
            - '\Microsoft\Windows\Start Menu\Programs\Startup\'
            - 'C:\Windows\TEMP\'
            - '\AppData\Local\Temp'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unlikely
level: high

```