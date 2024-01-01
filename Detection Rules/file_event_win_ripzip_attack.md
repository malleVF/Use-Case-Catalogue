---
title: "Potential RipZip Attack on Startup Folder"
status: "test"
created: "2022/07/21"
last_modified: "2023/01/05"
tags: [persistence, t1547, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Potential RipZip Attack on Startup Folder

### Description

Detects a phishing attack which expands a ZIP file containing a malicious shortcut.
If the victim expands the ZIP file via the explorer process, then the explorer process expands the malicious ZIP file and drops a malicious shortcut redirected to a backdoor into the Startup folder.
Additionally, the file name of the malicious shortcut in Startup folder contains {0AFACED1-E828-11D1-9187-B532F1E9575D} meaning the folder shortcut operation.


```yml
title: Potential RipZip Attack on Startup Folder
id: a6976974-ea6f-4e97-818e-ea08625c52cb
status: test
description: |
    Detects a phishing attack which expands a ZIP file containing a malicious shortcut.
    If the victim expands the ZIP file via the explorer process, then the explorer process expands the malicious ZIP file and drops a malicious shortcut redirected to a backdoor into the Startup folder.
    Additionally, the file name of the malicious shortcut in Startup folder contains {0AFACED1-E828-11D1-9187-B532F1E9575D} meaning the folder shortcut operation.
references:
    - https://twitter.com/jonasLyk/status/1549338335243534336?t=CrmPocBGLbDyE4p6zTX1cg&s=19
author: Greg (rule)
date: 2022/07/21
modified: 2023/01/05
tags:
    - attack.persistence
    - attack.t1547
logsource:
    category: file_event
    product: windows
detection:
    selection: # %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\target.lnk.{0AFACED1-E828-11D1-9187-B532F1E9575D}\target.lnk
        TargetFilename|contains|all:
            - '\Microsoft\Windows\Start Menu\Programs\Startup'
            - '.lnk.{0AFACED1-E828-11D1-9187-B532F1E9575D}'
        Image|endswith: '\explorer.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```