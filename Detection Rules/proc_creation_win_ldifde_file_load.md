---
title: "Import LDAP Data Interchange Format File Via Ldifde.EXE"
status: "experimental"
created: "2022/09/02"
last_modified: "2023/03/14"
tags: [command_and_control, defense_evasion, t1218, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Import LDAP Data Interchange Format File Via Ldifde.EXE

### Description

Detects the execution of "Ldifde.exe" with the import flag "-i". The can be abused to include HTTP-based arguments which will allow the arbitrary download of files from a remote server.


```yml
title: Import LDAP Data Interchange Format File Via Ldifde.EXE
id: 6f535e01-ca1f-40be-ab8d-45b19c0c8b7f
status: experimental
description: |
    Detects the execution of "Ldifde.exe" with the import flag "-i". The can be abused to include HTTP-based arguments which will allow the arbitrary download of files from a remote server.
references:
    - https://twitter.com/0gtweet/status/1564968845726580736
    - https://strontic.github.io/xcyclopedia/library/ldifde.exe-979DE101F5059CEC1D2C56967CA2BAC0.html
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731033(v=ws.11)
author: '@gott_cyber'
date: 2022/09/02
modified: 2023/03/14
tags:
    - attack.command_and_control
    - attack.defense_evasion
    - attack.t1218
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\ldifde.exe'
        - OriginalFileName: 'ldifde.exe'
    selection_cli:
        CommandLine|contains|all:
            - '-i'
            - '-f'
    condition: all of selection_*
falsepositives:
    - Since the content of the files are unknown, false positives are expected
level: medium

```