---
title: "Account Tampering - Suspicious Failed Logon Reasons"
status: "test"
created: "2017/02/19"
last_modified: "2022/06/29"
tags: [persistence, defense_evasion, privilege_escalation, initial_access, t1078, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "medium"
---

## Account Tampering - Suspicious Failed Logon Reasons

### Description

This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.

```yml
title: Account Tampering - Suspicious Failed Logon Reasons
id: 9eb99343-d336-4020-a3cd-67f3819e68ee
status: test
description: This method uses uncommon error codes on failed logons to determine suspicious activity and tampering with accounts that have been disabled or somehow restricted.
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
    - https://twitter.com/SBousseaden/status/1101431884540710913
author: Florian Roth (Nextron Systems)
date: 2017/02/19
modified: 2022/06/29
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.initial_access
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4625
            - 4776
        Status:
            - '0xC0000072'  # User logon to account disabled by administrator
            - '0xC000006F'  # User logon outside authorized hours
            - '0xC0000070'  # User logon from unauthorized workstation
            - '0xC0000413'  # Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine
            - '0xC000018C'  # The logon request failed because the trust relationship between the primary domain and the trusted domain failed
            - '0xC000015B'  # The user has not been granted the requested logon type (aka logon right) at this machine
    filter:
        SubjectUserSid: 'S-1-0-0'
    condition: selection and not filter
falsepositives:
    - User using a disabled account
level: medium

```