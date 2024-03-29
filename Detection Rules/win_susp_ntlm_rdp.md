---
title: "Potential Remote Desktop Connection to Non-Domain Host"
status: "test"
created: "2020/05/22"
last_modified: "2021/11/27"
tags: [command_and_control, t1219, detection_rule]
logsrc_product: "windows"
logsrc_service: "ntlm"
level: "medium"
---

## Potential Remote Desktop Connection to Non-Domain Host

### Description

Detects logons using NTLM to hosts that are potentially not part of the domain.

```yml
title: Potential Remote Desktop Connection to Non-Domain Host
id: ce5678bb-b9aa-4fb5-be4b-e57f686256ad
status: test
description: Detects logons using NTLM to hosts that are potentially not part of the domain.
references:
    - n/a
author: James Pemberton
date: 2020/05/22
modified: 2021/11/27
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    product: windows
    service: ntlm
    definition: Requires events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8001
        TargetName|startswith: 'TERMSRV'
    condition: selection
fields:
    - Computer
    - UserName
    - DomainName
    - TargetName
falsepositives:
    - Host connections to valid domains, exclude these.
    - Host connections not using host FQDN.
    - Host connections to external legitimate domains.
level: medium

```
