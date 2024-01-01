---
title: "Deleted Data Overwritten Via Cipher.EXE"
status: "experimental"
created: "2021/12/26"
last_modified: "2023/02/21"
tags: [impact, t1485, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Deleted Data Overwritten Via Cipher.EXE

### Description

Detects usage of the "cipher" built-in utility in order to overwrite deleted data from disk.
Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources.
Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives


```yml
title: Deleted Data Overwritten Via Cipher.EXE
id: 4b046706-5789-4673-b111-66f25fe99534
status: experimental
description: |
    Detects usage of the "cipher" built-in utility in order to overwrite deleted data from disk.
    Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources.
    Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1485/T1485.md#atomic-test-3---overwrite-deleted-data-on-c-drive
author: frack113
date: 2021/12/26
modified: 2023/02/21
tags:
    - attack.impact
    - attack.t1485
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName: 'CIPHER.EXE'
        - Image|endswith: '\cipher.exe'
    selection_cli:
        CommandLine|contains: ' /w:'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```