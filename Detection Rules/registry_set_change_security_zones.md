---
title: "IE Change Domain Zone"
status: "experimental"
created: "2022/01/22"
last_modified: "2023/08/17"
tags: [persistence, t1137, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## IE Change Domain Zone

### Description

Hides the file extension through modification of the registry

```yml
title: IE Change Domain Zone
id: 45e112d0-7759-4c2a-aa36-9f8fb79d3393
related:
    - id: d88d0ab2-e696-4d40-a2ed-9790064e66b3
      type: derived
status: experimental
description: Hides the file extension through modification of the registry
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1112/T1112.md#atomic-test-4---add-domain-to-trusted-sites-zone
    - https://docs.microsoft.com/en-us/troubleshoot/developer/browsers/security-privacy/ie-security-zones-registry-entries
author: frack113
date: 2022/01/22
modified: 2023/08/17
tags:
    - attack.persistence
    - attack.t1137
logsource:
    category: registry_set
    product: windows
detection:
    selection_domains:
        TargetObject|contains: \SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\
    filter:
        Details:
            - DWORD (0x00000000) # My Computer
            - DWORD (0x00000001) # Local Intranet Zone
            - '(Empty)'
    condition: selection_domains and not filter
falsepositives:
    - Administrative scripts
level: medium

```