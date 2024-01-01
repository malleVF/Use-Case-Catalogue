---
title: "CrackMapExec File Creation Patterns"
status: "test"
created: "2022/03/12"
last_modified: "2022/05/27"
tags: [credential_access, t1003_001, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## CrackMapExec File Creation Patterns

### Description

Detects suspicious file creation patterns found in logs when CrackMapExec is used

```yml
title: CrackMapExec File Creation Patterns
id: 9433ff9c-5d3f-4269-99f8-95fc826ea489
status: test
description: Detects suspicious file creation patterns found in logs when CrackMapExec is used
references:
    - https://mpgn.gitbook.io/crackmapexec/smb-protocol/obtaining-credentials/dump-lsass
author: Florian Roth (Nextron Systems)
date: 2022/03/12
modified: 2022/05/27
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    product: windows
    category: file_event
detection:
    selection_lsass_dump1:
        TargetFilename|startswith: 'C:\Windows\Temp\'
        Image: 'C:\WINDOWS\system32\rundll32.exe'
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
        TargetFilename|endswith:
            - '.rtf'
            - '.otf'
            - '.odt'
            - '.txt'
            - '.doc'
            - '.pdf'
            - '.dll'
            - '.docx'
            - '.wpd'
            - '.icns'
            - '.db'
            - '.ini'
            - '.tex'
            - '.sys'
            - '.csv'
            - '.fon'
            - '.tar'
            - '.ttf'
            - '.xml'
            - '.cfg'
            - '.cpl'
            - '.jpg'
            - '.drv'
            - '.cur'
            - '.tmp'
            # list is incomplete
    selection_procdump:
        TargetFilename: 'C:\Windows\Temp\procdump.exe'
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high

```