---
title: "Weak or Abused Passwords In CLI"
status: "test"
created: "2022/09/14"
last_modified: "2022/11/06"
tags: [defense_evasion, execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Weak or Abused Passwords In CLI

### Description

Detects weak passwords or often abused passwords (seen used by threat actors) via the CLI. An example would be a threat actor creating a new user via the net command and providing the password inline

```yml
title: Weak or Abused Passwords In CLI
id: 91edcfb1-2529-4ac2-9ecc-7617f895c7e4
status: test
description: Detects weak passwords or often abused passwords (seen used by threat actors) via the CLI. An example would be a threat actor creating a new user via the net command and providing the password inline
references:
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/espionage-asia-governments
    - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
    - https://www.microsoft.com/en-us/security/blog/2022/10/25/dev-0832-vice-society-opportunistic-ransomware-campaigns-impacting-us-education-sector/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/09/14
modified: 2022/11/06
tags:
    - attack.defense_evasion
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            # Add more passwords
            - 'Asd123.aaaa'
            - 'password123' # Also covers PASSWORD123123! as seen in https://www.microsoft.com/en-us/security/blog/2022/10/25/dev-0832-vice-society-opportunistic-ransomware-campaigns-impacting-us-education-sector/
            - '123456789'
            - 'P@ssw0rd!'
            - 'Decryptme'
    condition: selection
falsepositives:
    - Legitimate usage of the passwords by users via commandline (should be discouraged)
    - Other currently unknown false positives
level: medium

```
