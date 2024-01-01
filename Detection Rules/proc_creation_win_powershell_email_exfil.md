---
title: "Email Exifiltration Via Powershell"
status: "test"
created: "2022/09/09"
last_modified: ""
tags: [exfiltration, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Email Exifiltration Via Powershell

### Description

Detects email exfiltration via powershell cmdlets

```yml
title: Email Exifiltration Via Powershell
id: 312d0384-401c-4b8b-abdf-685ffba9a332
status: test
description: Detects email exfiltration via powershell cmdlets
references:
    - https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
    - https://github.com/Azure/Azure-Sentinel/blob/7e6aa438e254d468feec061618a7877aa528ee9f/Hunting%20Queries/Microsoft%20365%20Defender/Ransomware/DEV-0270/Email%20data%20exfiltration%20via%20PowerShell.yaml
author: Nasreddine Bencherchali (Nextron Systems),  Azure-Sentinel (idea)
date: 2022/09/09
tags:
    - attack.exfiltration
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains|all:
            - 'Add-PSSnapin'
            - 'Get-Recipient'
            - '-ExpandProperty'
            - 'EmailAddresses'
            - 'SmtpAddress'
            - '-hidetableheaders'
    condition: selection
falsepositives:
    - Unknown
level: high

```