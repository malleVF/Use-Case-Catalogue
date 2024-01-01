---
title: "Suspicious Execution of Hostname"
status: "test"
created: "2022/01/01"
last_modified: ""
tags: [discovery, t1082, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "low"
---

## Suspicious Execution of Hostname

### Description

Use of hostname to get information

```yml
title: Suspicious Execution of Hostname
id: 7be5fb68-f9ef-476d-8b51-0256ebece19e
status: test
description: Use of hostname to get information
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md#atomic-test-6---hostname-discovery-windows
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/hostname
author: frack113
date: 2022/01/01
tags:
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\HOSTNAME.EXE'
    condition: selection
falsepositives:
    - Unknown
level: low

```
