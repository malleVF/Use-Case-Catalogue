---
title: "Certificate Exported Via Certutil.EXE"
status: "test"
created: "2023/02/15"
last_modified: "2023/02/20"
tags: [defense_evasion, t1027, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Certificate Exported Via Certutil.EXE

### Description

Detects the execution of the certutil with the "exportPFX" flag which allows the utility to export certificates.

```yml
title: Certificate Exported Via Certutil.EXE
id: 3ffd6f51-e6c1-47b7-94b4-c1e61d4117c5
status: test
description: Detects the execution of the certutil with the "exportPFX" flag which allows the utility to export certificates.
references:
    - https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html
author: Florian Roth (Nextron Systems), Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/15
modified: 2023/02/20
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
    selection_cli:
        CommandLine|contains:
            - '-exportPFX '
            - '/exportPFX '
    condition: all of selection_*
falsepositives:
    - There legitimate reasons to export certificates. Investigate the activity to determine if it's benign
level: medium

```