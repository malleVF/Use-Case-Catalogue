---
title: "Kavremover Dropped Binary LOLBIN Usage"
status: "test"
created: "2022/11/01"
last_modified: ""
tags: [defense_evasion, t1127, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Kavremover Dropped Binary LOLBIN Usage

### Description

Detects the execution of a signed binary dropped by Kaspersky Lab Products Remover (kavremover) which can be abused as a LOLBIN to execute arbitrary commands and binaries.

```yml
title: Kavremover Dropped Binary LOLBIN Usage
id: d047726b-c71c-4048-a99b-2e2f50dc107d
status: test
description: Detects the execution of a signed binary dropped by Kaspersky Lab Products Remover (kavremover) which can be abused as a LOLBIN to execute arbitrary commands and binaries.
references:
    - https://nasbench.medium.com/lolbined-using-kaspersky-endpoint-security-kes-installer-to-execute-arbitrary-commands-1c999f1b7fea
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/11/01
tags:
    - attack.defense_evasion
    - attack.t1127
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: ' run run-cmd '
    filter:
        ParentImage|endswith:
            - '\kavremover.exe' # When launched from kavremover.exe
            - '\cleanapi.exe' # When launched from KES installer
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
