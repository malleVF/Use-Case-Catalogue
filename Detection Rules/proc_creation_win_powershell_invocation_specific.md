---
title: "Suspicious PowerShell Invocations - Specific - ProcessCreation"
status: "test"
created: "2023/01/05"
last_modified: ""
tags: [defense_evasion, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious PowerShell Invocations - Specific - ProcessCreation

### Description

Detects suspicious PowerShell invocation command parameters

```yml
title: Suspicious PowerShell Invocations - Specific - ProcessCreation
id: 536e2947-3729-478c-9903-745aaffe60d2
related:
    - id: fce5f582-cc00-41e1-941a-c6fabf0fdb8c
      type: derived
    - id: ae7fbf8e-f3cb-49fd-8db4-5f3bed522c71
      type: similar
    - id: 8ff28fdd-e2fa-4dfa-aeda-ef3d61c62090
      type: similar
status: test
description: Detects suspicious PowerShell invocation command parameters
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/01/05
tags:
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_convert_b64:
        CommandLine|contains|all:
            - '-nop'
            - ' -w '
            - 'hidden'
            - ' -c '
            - '[Convert]::FromBase64String'
    selection_iex:
        CommandLine|contains|all:
            - ' -w '
            - 'hidden'
            - '-noni'
            - '-nop'
            - ' -c '
            - 'iex'
            - 'New-Object'
    selection_enc:
        CommandLine|contains|all:
            - ' -w '
            - 'hidden'
            - '-ep'
            - 'bypass'
            - '-Enc'
    selection_reg:
        CommandLine|contains|all:
            - 'powershell'
            - 'reg'
            - 'add'
            - '\software\'
    selection_webclient:
        CommandLine|contains|all:
            - 'bypass'
            - '-noprofile'
            - '-windowstyle'
            - 'hidden'
            - 'new-object'
            - 'system.net.webclient'
            - '.download'
    selection_iex_webclient:
        CommandLine|contains|all:
            - 'iex'
            - 'New-Object'
            - 'Net.WebClient'
            - '.Download'
    filter_chocolatey:
        CommandLine|contains:
            - "(New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1"
            - 'Write-ChocolateyWarning'
    condition: 1 of selection_* and not 1 of filter_*
falsepositives:
    - Unknown
level: medium

```
