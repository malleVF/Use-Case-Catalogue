---
title: "Microsoft Binary Suspicious Communication Endpoint"
status: "test"
created: "2018/08/30"
last_modified: "2023/08/17"
tags: [lateral_movement, t1105, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Microsoft Binary Suspicious Communication Endpoint

### Description

Detects an executable in the Windows folder accessing suspicious domains

```yml
title: Microsoft Binary Suspicious Communication Endpoint
id: e0f8ab85-0ac9-423b-a73a-81b3c7b1aa97
related:
    - id: 635dbb88-67b3-4b41-9ea5-a3af2dd88153
      type: obsoletes
status: test
description: Detects an executable in the Windows folder accessing suspicious domains
references:
    - https://twitter.com/M_haggis/status/900741347035889665
    - https://twitter.com/M_haggis/status/1032799638213066752
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
    - https://www.cisa.gov/uscert/ncas/alerts/aa22-321a
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/exfil/Invoke-ExfilDataToGitHub.ps1
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2018/08/30
modified: 2023/08/17
tags:
    - attack.lateral_movement
    - attack.t1105
logsource:
    category: network_connection
    product: windows
detection:
    selection_paths:
        - Image|startswith:
              - 'C:\PerfLogs'
              - 'C:\Temp\'
              - 'C:\Users\Public\'
              - 'C:\Windows\'
        - Image|contains: '\AppData\Temp\'
    selection_domains:
        Initiated: 'true'
        DestinationHostname|endswith:
            - '.githubusercontent.com'       # Includes both gists and github repositories / Michael Haag (idea)
            - 'anonfiles.com'
            - 'cdn.discordapp.com'
            - 'cdn.discordapp.com/attachments/'
            - 'ddns.net'
            - 'dl.dropboxusercontent.com'
            - 'ghostbin.co'
            - 'gofile.io'
            - 'hastebin.com'
            - 'mediafire.com'
            - 'mega.nz'
            - 'paste.ee'
            - 'pastebin.com'
            - 'pastebin.pl'
            - 'pastetext.net'
            - 'privatlab.com'
            - 'privatlab.net'
            - 'send.exploit.in'
            - 'sendspace.com'
            - 'storage.googleapis.com'
            - 'storjshare.io'
            - 'temp.sh'
            - 'transfer.sh'
            - 'ufile.io'
    condition: all of selection_*
falsepositives:
    - Unknown
    - '@subTee in your network'
level: high

```
