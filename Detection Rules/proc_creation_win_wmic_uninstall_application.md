---
title: "Application Removed Via Wmic.EXE"
status: "experimental"
created: "2022/01/28"
last_modified: "2023/02/14"
tags: [execution, t1047, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Application Removed Via Wmic.EXE

### Description

Uninstall an application with wmic

```yml
title: Application Removed Via Wmic.EXE
id: b53317a0-8acf-4fd1-8de8-a5401e776b96
related:
    - id: 847d5ff3-8a31-4737-a970-aeae8fe21765 # Uninstall Security Products
      type: derived
status: experimental
description: Uninstall an application with wmic
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1047/T1047.md#atomic-test-10---application-uninstall-using-wmic
author: frack113
date: 2022/01/28
modified: 2023/02/14
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\WMIC.exe'
        - OriginalFileName: 'wmic.exe'
    selection_cli:
        CommandLine|contains:
            - 'call'
            - 'uninstall'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```