---
title: "First Time Seen Remote Named Pipe - Zeek"
status: "test"
created: "2020/04/02"
last_modified: "2022/12/27"
tags: [lateral_movement, t1021_002, detection_rule]
logsrc_product: "zeek"
logsrc_service: "smb_files"
level: "high"
---

## First Time Seen Remote Named Pipe - Zeek

### Description

This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes

```yml
title: First Time Seen Remote Named Pipe - Zeek
id: 021310d9-30a6-480a-84b7-eaa69aeb92bb
related:
    - id: 52d8b0c6-53d6-439a-9e41-52ad442ad9ad
      type: derived
status: test
description: This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes
references:
    - https://twitter.com/menasec1/status/1104489274387451904
author: Samir Bousseaden, @neu5ron, Tim Shelton
date: 2020/04/02
modified: 2022/12/27
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    product: zeek
    service: smb_files
detection:
    selection:
        path: '\\\\\*\\IPC$' # Looking for the string \\*\IPC$
    filter_keywords:
        - 'samr'
        - 'lsarpc'
        - 'winreg'
        - 'netlogon'
        - 'srvsvc'
        - 'protected_storage'
        - 'wkssvc'
        - 'browser'
        - 'netdfs'
        - 'svcctl'
        - 'spoolss'
        - 'ntsvcs'
        - 'LSM_API_service'
        - 'HydraLsPipe'
        - 'TermSrv_API_service'
        - 'MsFteWds'
    condition: selection and not 1 of filter_*
falsepositives:
    - Update the excluded named pipe to filter out any newly observed legit named pipe
level: high

```
