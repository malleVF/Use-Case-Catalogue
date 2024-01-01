---
title: "Ruby Inline Command Execution"
status: "test"
created: "2023/01/02"
last_modified: ""
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Ruby Inline Command Execution

### Description

Detects execution of ruby using the "-e" flag. This is could be used as a way to launch a reverse shell or execute live ruby code.

```yml
title: Ruby Inline Command Execution
id: 20a5ffa1-3848-4584-b6f8-c7c7fd9f69c8
status: test
description: Detects execution of ruby using the "-e" flag. This is could be used as a way to launch a reverse shell or execute live ruby code.
references:
    - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
    - https://www.revshells.com/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/01/02
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\ruby.exe'
        - OriginalFileName: 'ruby.exe'
    selection_cli:
        CommandLine|contains: ' -e'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```