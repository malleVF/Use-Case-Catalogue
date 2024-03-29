---
title: "Cscript/Wscript Uncommon Script Extension Execution"
status: "experimental"
created: "2023/05/15"
last_modified: "2023/06/19"
tags: [execution, t1059_005, t1059_007, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Cscript/Wscript Uncommon Script Extension Execution

### Description

Detects Wscript/Cscript executing a file with an uncommon (i.e. non-script) extension

```yml
title: Cscript/Wscript Uncommon Script Extension Execution
id: 99b7460d-c9f1-40d7-a316-1f36f61d52ee
status: experimental
description: Detects Wscript/Cscript executing a file with an uncommon (i.e. non-script) extension
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/05/15
modified: 2023/06/19
tags:
    - attack.execution
    - attack.t1059.005
    - attack.t1059.007
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName:
              - 'wscript.exe'
              - 'cscript.exe'
        - Image|endswith:
              - '\wscript.exe'
              - '\cscript.exe'
    selection_extension:
        CommandLine|contains:
            # Note: add additional potential suspicious extension
            # We could specify the "//E:" flag to avoid typos by admin. But since that's prone to blind spots via the creation of assoc it's better not to include it
            - '.csv'
            - '.dat'
            - '.doc'
            - '.gif'
            - '.jpeg'
            - '.jpg'
            - '.png'
            - '.ppt'
            - '.txt'
            - '.xls'
            - '.xml'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```
