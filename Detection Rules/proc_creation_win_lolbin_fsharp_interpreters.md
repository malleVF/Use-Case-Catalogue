---
title: "Use of FSharp Interpreters"
status: "test"
created: "2022/06/02"
last_modified: ""
tags: [execution, t1059, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Use of FSharp Interpreters

### Description

The FSharp Interpreters, FsiAnyCpu.exe and FSi.exe, can be used for AWL bypass and is listed in Microsoft recommended block rules.

```yml
title: Use of FSharp Interpreters
id: b96b2031-7c17-4473-afe7-a30ce714db29
status: test
description: The FSharp Interpreters, FsiAnyCpu.exe and FSi.exe, can be used for AWL bypass and is listed in Microsoft recommended block rules.
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules
    - https://bohops.com/2020/11/02/exploring-the-wdac-microsoft-recommended-block-rules-part-ii-wfc-fsi/
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/FsiAnyCpu/
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Fsi/
author: 'Christopher Peacock @SecurePeacock, SCYTHE @scythe_io'
date: 2022/06/02
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\fsianycpu.exe'
        - OriginalFileName: 'fsianycpu.exe'
        - Image|endswith: '\fsi.exe'
        - OriginalFileName: 'fsi.exe'
    condition: selection
falsepositives:
    - Legitimate use by a software developer.
level: medium

```
