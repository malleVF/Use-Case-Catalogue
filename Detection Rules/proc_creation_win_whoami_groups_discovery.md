---
title: "Group Membership Reconnaissance Via Whoami.EXE"
status: "experimental"
created: "2023/02/28"
last_modified: ""
tags: [discovery, t1033, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Group Membership Reconnaissance Via Whoami.EXE

### Description

Detects the execution of whoami.exe with the /group command line flag to show group membership for the current user, account type, security identifiers (SID), and attributes.

```yml
title: Group Membership Reconnaissance Via Whoami.EXE
id: bd8b828d-0dca-48e1-8a63-8a58ecf2644f
status: experimental
description: Detects the execution of whoami.exe with the /group command line flag to show group membership for the current user, account type, security identifiers (SID), and attributes.
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/28
tags:
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\whoami.exe'
        - OriginalFileName: 'whoami.exe'
    selection_cli:
        CommandLine|contains:
            - ' /groups'
            - ' -groups'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
