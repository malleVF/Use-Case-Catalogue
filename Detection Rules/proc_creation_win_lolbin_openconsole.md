---
title: "Use of OpenConsole"
status: "test"
created: "2022/06/16"
last_modified: ""
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Use of OpenConsole

### Description

Detects usage of OpenConsole binary as a LOLBIN to launch other binaries to bypass application Whitelisting

```yml
title: Use of OpenConsole
id: 814c95cc-8192-4378-a70a-f1aafd877af1
status: test
description: Detects usage of OpenConsole binary as a LOLBIN to launch other binaries to bypass application Whitelisting
references:
    - https://twitter.com/nas_bench/status/1537563834478645252
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/06/16
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - OriginalFileName: 'OpenConsole.exe'
        - Image|endswith: '\OpenConsole.exe'
    filter:
        Image|startswith: 'C:\Program Files\WindowsApps\Microsoft.WindowsTerminal' # We exclude the default path for WindowsTerminal
    condition: selection and not filter
falsepositives:
    - Legitimate use by an administrator
level: medium

```
