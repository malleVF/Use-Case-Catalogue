---
title: "Esentutl Gather Credentials"
status: "test"
created: "2021/08/06"
last_modified: "2022/10/09"
tags: [credential_access, t1003, t1003_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Esentutl Gather Credentials

### Description

Conti recommendation to its affiliates to use esentutl to access NTDS dumped file. Trickbot also uses this utilities to get MSEdge info via its module pwgrab.

```yml
title: Esentutl Gather Credentials
id: 7df1713a-1a5b-4a4b-a071-dc83b144a101
status: test
description: Conti recommendation to its affiliates to use esentutl to access NTDS dumped file. Trickbot also uses this utilities to get MSEdge info via its module pwgrab.
references:
    - https://twitter.com/vxunderground/status/1423336151860002816
    - https://attack.mitre.org/software/S0404/
    - https://thedfirreport.com/2021/08/01/bazarcall-to-conti-ransomware-via-trickbot-and-cobalt-strike/
author: sam0x90
date: 2021/08/06
modified: 2022/10/09
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'esentutl'
            - ' /p'
    condition: selection
fields:
    - User
    - CommandLine
    - ParentCommandLine
    - CurrentDirectory
falsepositives:
    - To be determined
level: medium

```
