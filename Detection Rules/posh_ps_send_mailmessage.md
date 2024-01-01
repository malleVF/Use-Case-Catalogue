---
title: "Powershell Exfiltration Over SMTP"
status: "test"
created: "2022/09/26"
last_modified: ""
tags: [exfiltration, t1048_003, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Powershell Exfiltration Over SMTP

### Description

Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.
The data may also be sent to an alternate network location from the main command and control server.


```yml
title: Powershell Exfiltration Over SMTP
id: 9a7afa56-4762-43eb-807d-c3dc9ffe211b
status: test
description: |
    Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.
    The data may also be sent to an alternate network location from the main command and control server.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1048.003/T1048.003.md#atomic-test-5---exfiltration-over-alternative-protocol---smtp
    - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/send-mailmessage?view=powershell-7.2
    - https://www.ietf.org/rfc/rfc2821.txt
author: frack113
date: 2022/09/26
tags:
    - attack.exfiltration
    - attack.t1048.003
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: 'Send-MailMessage'
    filter:
        ScriptBlockText|contains: 'CmdletsToExport'
    condition: selection and not filter
falsepositives:
    - Legitimate script
level: medium

```