---
title: "Suspicious DLL Loaded via CertOC.EXE"
status: "experimental"
created: "2023/02/15"
last_modified: ""
tags: [defense_evasion, t1218, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious DLL Loaded via CertOC.EXE

### Description

Detects when a user installs certificates by using CertOC.exe to load the target DLL file.

```yml
title: Suspicious DLL Loaded via CertOC.EXE
id: 84232095-ecca-4015-b0d7-7726507ee793
related:
    - id: 242301bc-f92f-4476-8718-78004a6efd9f
      type: similar
status: experimental
description: Detects when a user installs certificates by using CertOC.exe to load the target DLL file.
references:
    - https://twitter.com/sblmsrsn/status/1445758411803480072?s=20
    - https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-fe98e74189873d6df72a15df2eaa0315c59ba9cdaca93ecd68afc4ea09194ef2
    - https://lolbas-project.github.io/lolbas/Binaries/Certoc/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/15
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certoc.exe'
        - OriginalFileName: 'CertOC.exe'
    selection_cli:
        CommandLine|contains:
            - ' -LoadDLL '
            - ' /LoadDLL '
    selection_paths:
        CommandLine|contains:
            - '\Appdata\Local\Temp\'
            - '\Desktop\'
            - '\Downloads\'
            - '\Users\Public\'
            - 'C:\Windows\Tasks\'
            - 'C:\Windows\Temp\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high

```