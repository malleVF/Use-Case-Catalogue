---
title: "DirLister Execution"
status: "test"
created: "2022/08/20"
last_modified: "2023/02/04"
tags: [discovery, t1083, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## DirLister Execution

### Description

Detect the usage of "DirLister.exe" a utility for quickly listing folder or drive contents. It was seen used by BlackCat ransomware to create a list of accessible directories and files.

```yml
title: DirLister Execution
id: b4dc61f5-6cce-468e-a608-b48b469feaa2
status: test
description: Detect the usage of "DirLister.exe" a utility for quickly listing folder or drive contents. It was seen used by BlackCat ransomware to create a list of accessible directories and files.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1083/T1083.md
    - https://news.sophos.com/en-us/2022/07/14/blackcat-ransomware-attacks-not-merely-a-byproduct-of-bad-luck/
author: frack113
date: 2022/08/20
modified: 2023/02/04
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - OriginalFileName: 'DirLister.exe'
        - Image|endswith: '\dirlister.exe'
    condition: selection
falsepositives:
    - Legitimate use by users
level: low

```