---
title: "Curl Web Request With Potential Custom User-Agent"
status: "experimental"
created: "2023/07/27"
last_modified: ""
tags: [execution, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Curl Web Request With Potential Custom User-Agent

### Description

Detects execution of "curl.exe" with a potential custom "User-Agent". Attackers can leverage this to download or exfiltrate data via "curl" to a domain that only accept specific "User-Agent" strings

```yml
title: Curl Web Request With Potential Custom User-Agent
id: 85de1f22-d189-44e4-8239-dc276b45379b
status: experimental
description: Detects execution of "curl.exe" with a potential custom "User-Agent". Attackers can leverage this to download or exfiltrate data via "curl" to a domain that only accept specific "User-Agent" strings
references:
    - https://labs.withsecure.com/publications/fin7-target-veeam-servers
    - https://github.com/WithSecureLabs/iocs/blob/344203de742bb7e68bd56618f66d34be95a9f9fc/FIN7VEEAM/iocs.csv
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/07/27
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\curl.exe'
        - OriginalFileName: 'curl.exe'
    selection_header:
        CommandLine|re: '\s-H\s' # Must be Regex as the flag needs to be case sensitive
        CommandLine|contains: 'User-Agent:'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium

```
