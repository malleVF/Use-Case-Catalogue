---
title: "Suspicious Download Via Certutil.EXE"
status: "test"
created: "2023/02/15"
last_modified: ""
tags: [defense_evasion, t1027, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Download Via Certutil.EXE

### Description

Detects the execution of certutil with certain flags that allow the utility to download files.

```yml
title: Suspicious Download Via Certutil.EXE
id: 19b08b1c-861d-4e75-a1ef-ea0c1baf202b
related:
    - id: 13e6fe51-d478-4c7e-b0f2-6da9b400a829
      type: similar
status: test
description: Detects the execution of certutil with certain flags that allow the utility to download files.
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
    - https://forensicitguy.github.io/agenttesla-vba-certutil-download/
    - https://news.sophos.com/en-us/2021/04/13/compromised-exchange-server-hosting-cryptojacker-targeting-other-exchange-servers/
    - https://twitter.com/egre55/status/1087685529016193025
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/15
tags:
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_flags:
        CommandLine|contains:
            - 'urlcache '
            - 'verifyctl '
    selection_http:
        CommandLine|contains: 'http'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```