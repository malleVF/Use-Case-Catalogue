---
title: "Obfuscated IP Download Activity"
status: "test"
created: "2022/08/03"
last_modified: "2023/11/06"
tags: [discovery, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Obfuscated IP Download Activity

### Description

Detects use of an encoded/obfuscated version of an IP address (hex, octal...) in an URL combined with a download command

```yml
title: Obfuscated IP Download Activity
id: cb5a2333-56cf-4562-8fcb-22ba1bca728d
status: test
description: Detects use of an encoded/obfuscated version of an IP address (hex, octal...) in an URL combined with a download command
references:
    - https://h.43z.one/ipconverter/
    - https://twitter.com/Yasser_Elsnbary/status/1553804135354564608
    - https://twitter.com/fr0s7_/status/1712780207105404948
author: Florian Roth (Nextron Systems), X__Junior (Nextron Systems)
date: 2022/08/03
modified: 2023/11/06
tags:
    - attack.discovery
logsource:
    category: process_creation
    product: windows
detection:
    selection_command:
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'iwr '
            - 'wget '
            - 'curl '
            - 'DownloadFile'
            - 'DownloadString'
    selection_ip_1:
        CommandLine|contains:
            - ' 0x'
            - '//0x'
            - '.0x'
            - '.00x'
    selection_ip_2:
        CommandLine|contains|all:
            - 'http://%'
            - '%2e'
    selection_ip_3:
        # http://81.4.31754
        - CommandLine|re: 'https?://[0-9]{1,3}\.[0-9]{1,3}\.0[0-9]{3,4}'
        # http://81.293898
        - CommandLine|re: 'https?://[0-9]{1,3}\.0[0-9]{3,7}'
        # http://1359248394
        - CommandLine|re: 'https?://0[0-9]{3,11}'
        # http://0121.04.0174.012
        - CommandLine|re: 'https?://(0[0-9]{1,11}\.){3}0[0-9]{1,11}'
        # http://012101076012
        - CommandLine|re: 'https?://0[0-9]{1,11}'
        # For octal format
        - CommandLine|re: ' [0-7]{7,13}'
    filter_main_valid_ip:
        CommandLine|re: 'https?://((25[0-5]|(2[0-4]|1\d|[1-9])?\d)(\.|\b)){4}'
    condition: selection_command and 1 of selection_ip_* and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium

```