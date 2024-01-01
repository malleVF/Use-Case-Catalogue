---
title: "Manipulation of User Computer or Group Security Principals Across AD"
status: "test"
created: "2021/12/28"
last_modified: ""
tags: [persistence, t1136_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Manipulation of User Computer or Group Security Principals Across AD

### Description

Adversaries may create a domain account to maintain access to victim systems.
Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain..


```yml
title: Manipulation of User Computer or Group Security Principals Across AD
id: b29a93fb-087c-4b5b-a84d-ee3309e69d08
status: test
description: |
    Adversaries may create a domain account to maintain access to victim systems.
    Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain..
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1136.002/T1136.002.md#atomic-test-3---create-a-new-domain-account-using-powershell
    - https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement?view=dotnet-plat-ext-6.0
author: frack113
date: 2021/12/28
tags:
    - attack.persistence
    - attack.t1136.002
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains: System.DirectoryServices.AccountManagement
    condition: selection
falsepositives:
    - Legitimate administrative script
level: medium

```