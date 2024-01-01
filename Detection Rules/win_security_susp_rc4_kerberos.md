---
title: "Suspicious Kerberos RC4 Ticket Encryption"
status: "test"
created: "2017/02/06"
last_modified: "2022/06/19"
tags: [credential_access, t1558_003, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Suspicious Kerberos RC4 Ticket Encryption

### Description

Detects service ticket requests using RC4 encryption type

```yml
title: Suspicious Kerberos RC4 Ticket Encryption
id: 496a0e47-0a33-4dca-b009-9e6ca3591f39
status: test
description: Detects service ticket requests using RC4 encryption type
references:
    - https://adsecurity.org/?p=3458
    - https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity
author: Florian Roth (Nextron Systems)
date: 2017/02/06
modified: 2022/06/19
tags:
    - attack.credential_access
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketOptions: '0x40810000'
        TicketEncryptionType: '0x17'
    reduction:
        ServiceName|endswith: '$'
    condition: selection and not reduction
falsepositives:
    - Service accounts used on legacy systems (e.g. NetApp)
    - Windows Domains with DFL 2003 and legacy systems
level: medium

```
