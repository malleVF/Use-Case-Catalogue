---
title: "Unusual File Download from Direct IP Address"
status: "experimental"
created: "2022/09/07"
last_modified: "2023/02/10"
tags: [defense_evasion, t1564_004, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Unusual File Download from Direct IP Address

### Description

Detects the download of suspicious file type from URLs with IP

```yml
title: Unusual File Download from Direct IP Address
id: 025bd229-fd1f-4fdb-97ab-20006e1a5368
status: experimental
description: Detects the download of suspicious file type from URLs with IP
references:
    - https://github.com/trustedsec/SysmonCommunityGuide/blob/adcdfee20999f422b974c8d4149bf4c361237db7/chapters/file-stream-creation-hash.md
    - https://labs.withsecure.com/publications/detecting-onenote-abuse
author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
date: 2022/09/07
modified: 2023/02/10
tags:
    - attack.defense_evasion
    - attack.t1564.004
logsource:
    product: windows
    category: create_stream_hash
detection:
    selection:
        Contents|re: 'http[s]?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
        TargetFilename|contains:
            - '.ps1:Zone'
            - '.bat:Zone'
            - '.exe:Zone'
            - '.vbe:Zone'
            - '.vbs:Zone'
            - '.dll:Zone'
            - '.one:Zone'
            - '.cmd:Zone'
            - '.hta:Zone'
            - '.xll:Zone'
            - '.lnk:Zone'
    condition: selection
falsepositives:
    - Unknown
level: high

```
