---
title: "Wlrmdr Lolbin Use as Launcher"
status: "test"
created: "2022/02/16"
last_modified: "2022/12/06"
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Wlrmdr Lolbin Use as Launcher

### Description

Detects use of Wlrmdr.exe in which the -u parameter is passed to ShellExecute

```yml
title: Wlrmdr Lolbin Use as Launcher
id: 9cfc00b6-bfb7-49ce-9781-ef78503154bb
status: test
description: Detects use of Wlrmdr.exe in which the -u parameter is passed to ShellExecute
references:
    - https://twitter.com/0gtweet/status/1493963591745220608?s=20&t=xUg9DsZhJy1q9bPTUWgeIQ
author: frack113, manasmbellani
date: 2022/02/16
modified: 2022/12/06
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_child_img:
        - Image|endswith: '\wlrmdr.exe'
        - OriginalFileName: 'WLRMNDR.EXE'
    selection_child_cli:
        CommandLine|contains|all:
            # Note that the dash "-" can be replaced with a slash "/" (TODO: Use the "windash" modifier when it's introduced)
            - '-s '
            - '-f '
            - '-t '
            - '-m '
            - '-a '
            - '-u '
    selection_parent: # This selection is looking for processes spawned from wlrmdr using the "-u" flag
        ParentImage|endswith: '\wlrmdr.exe'
    filter:
        ParentImage: 'C:\Windows\System32\winlogon.exe'
    filter_null:
        ParentImage: '-'
    condition: selection_parent or (all of selection_child_* and not 1 of filter*)
falsepositives:
    - Unknown
level: medium

```
