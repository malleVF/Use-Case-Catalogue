---
title: "Suspicious Download from Office Domain"
status: "test"
created: "2021/12/27"
last_modified: "2022/08/02"
tags: [command_and_control, t1105, t1608, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Download from Office Domain

### Description

Detects suspicious ways to download files from Microsoft domains that are used to store attachments in Emails or OneNote documents

```yml
title: Suspicious Download from Office Domain
id: 00d49ed5-4491-4271-a8db-650a4ef6f8c1
status: test
description: Detects suspicious ways to download files from Microsoft domains that are used to store attachments in Emails or OneNote documents
references:
    - https://twitter.com/an0n_r0/status/1474698356635193346?s=12
    - https://twitter.com/mrd0x/status/1475085452784844803?s=12
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2021/12/27
modified: 2022/08/02
tags:
    - attack.command_and_control
    - attack.t1105
    - attack.t1608
logsource:
    product: windows
    category: process_creation
detection:
    selection_download:
        - Image|endswith:
              - '\curl.exe'
              - '\wget.exe'
        - CommandLine|contains:
              - 'Invoke-WebRequest'
              - 'iwr '
              - 'curl '
              - 'wget '
              - 'Start-BitsTransfer'
              - '.DownloadFile('
              - '.DownloadString('
    selection_domains:
        CommandLine|contains:
            - 'https://attachment.outlook.live.net/owa/'
            - 'https://onenoteonlinesync.onenote.com/onenoteonlinesync/'
    condition: all of selection_*
falsepositives:
    - Scripts or tools that download attachments from these domains (OneNote, Outlook 365)
level: high

```