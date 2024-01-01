---
title: "Potential Active Directory Enumeration Using AD Module - PsScript"
status: "test"
created: "2023/01/22"
last_modified: ""
tags: [reconnaissance, discovery, impact, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Potential Active Directory Enumeration Using AD Module - PsScript

### Description

Detects usage of the "Import-Module" cmdlet to load the "Microsoft.ActiveDirectory.Management.dl" DLL. Which is often used by attackers to perform AD enumeration.

```yml
title: Potential Active Directory Enumeration Using AD Module - PsScript
id: 9e620995-f2d8-4630-8430-4afd89f77604
related:
    - id: 70bc5215-526f-4477-963c-a47a5c9ebd12
      type: similar
    - id: 74176142-4684-4d8a-8b0a-713257e7df8e
      type: similar
status: test
description: Detects usage of the "Import-Module" cmdlet to load the "Microsoft.ActiveDirectory.Management.dl" DLL. Which is often used by attackers to perform AD enumeration.
references:
    - https://github.com/samratashok/ADModule
    - https://twitter.com/cyb3rops/status/1617108657166061568?s=20
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges
author: frack113, Nasreddine Bencherchali
date: 2023/01/22
tags:
    - attack.reconnaissance
    - attack.discovery
    - attack.impact
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enable'
detection:
    selection_generic:
        ScriptBlockText|contains|all:
            - 'Import-Module '
            - 'Microsoft.ActiveDirectory.Management.dll'
    selection_specific:
        ScriptBlockText|contains: 'ipmo Microsoft.ActiveDirectory.Management.dll'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of the library for administrative activity
level: medium

```