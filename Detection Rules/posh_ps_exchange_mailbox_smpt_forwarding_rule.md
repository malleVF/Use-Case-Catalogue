---
title: "Suspicious PowerShell Mailbox SMTP Forward Rule"
status: "test"
created: "2022/10/26"
last_modified: ""
tags: [exfiltration, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious PowerShell Mailbox SMTP Forward Rule

### Description

Detects usage of the powerShell Set-Mailbox Cmdlet to set-up an SMTP forwarding rule.

```yml
title: Suspicious PowerShell Mailbox SMTP Forward Rule
id: 15b7abbb-8b40-4d01-9ee2-b51994b1d474
status: test
description: Detects usage of the powerShell Set-Mailbox Cmdlet to set-up an SMTP forwarding rule.
references:
    - https://m365internals.com/2022/10/07/hunting-in-on-premises-exchange-server-logs/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022/10/26
tags:
    - attack.exfiltration
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Set-Mailbox '
            - ' -DeliverToMailboxAndForward '
            - ' -ForwardingSmtpAddress '
    condition: selection
falsepositives:
    - Legitimate usage of the cmdlet to forward emails
level: medium

```
