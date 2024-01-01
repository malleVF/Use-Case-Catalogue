---
title: "Suspicious Microsoft Office Child Process - MacOS"
status: "test"
created: "2023/01/31"
last_modified: "2023/02/04"
tags: [execution, persistence, t1059_002, t1137_002, t1204_002, detection_rule]
logsrc_product: "macos"
logsrc_service: ""
level: "high"
---

## Suspicious Microsoft Office Child Process - MacOS

### Description

Detects suspicious child processes spawning from microsoft office suite applications such as word or excel. This could indicates malicious macro execution

```yml
title: Suspicious Microsoft Office Child Process - MacOS
id: 69483748-1525-4a6c-95ca-90dc8d431b68
status: test
description: Detects suspicious child processes spawning from microsoft office suite applications such as word or excel. This could indicates malicious macro execution
references:
    - https://redcanary.com/blog/applescript/
    - https://objective-see.org/blog/blog_0x4B.html
author: Sohan G (D4rkCiph3r)
date: 2023/01/31
modified: 2023/02/04
tags:
    - attack.execution
    - attack.persistence
    - attack.t1059.002
    - attack.t1137.002
    - attack.t1204.002
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        ParentImage|contains:
            - 'Microsoft Word'
            - 'Microsoft Excel'
            - 'Microsoft PowerPoint'
            - 'Microsoft OneNote'
        Image|endswith:
            - '/bash'
            - '/curl'
            - '/dash'
            - '/fish'
            - '/osacompile'
            - '/osascript'
            - '/sh'
            - '/zsh'
            - '/python'
            - '/python3'
            - '/wget'
    condition: selection
falsepositives:
    - Unknown
level: high

```
