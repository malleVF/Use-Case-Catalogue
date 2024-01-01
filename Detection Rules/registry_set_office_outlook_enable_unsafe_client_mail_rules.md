---
title: "Outlook EnableUnsafeClientMailRules Setting Enabled - Registry"
status: "experimental"
created: "2023/02/08"
last_modified: "2023/08/17"
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Outlook EnableUnsafeClientMailRules Setting Enabled - Registry

### Description

Detects an attacker trying to enable the outlook security setting "EnableUnsafeClientMailRules" which allows outlook to run applications or execute macros

```yml
title: Outlook EnableUnsafeClientMailRules Setting Enabled - Registry
id: 6763c6c8-bd01-4687-bc8d-4fa52cf8ba08
related:
    - id: c3cefdf4-6703-4e1c-bad8-bf422fc5015a
      type: similar
    - id: 55f0a3a1-846e-40eb-8273-677371b8d912 # ProcCreation variation
      type: similar
status: experimental
description: Detects an attacker trying to enable the outlook security setting "EnableUnsafeClientMailRules" which allows outlook to run applications or execute macros
references:
    - https://support.microsoft.com/en-us/topic/how-to-control-the-rule-actions-to-start-an-application-or-run-a-macro-in-outlook-2016-and-outlook-2013-e4964b72-173c-959d-5d7b-ead562979048
    - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=44
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/08
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith: '\Outlook\Security\EnableUnsafeClientMailRules'
        Details: 'DWORD (0x00000001)'
    condition: selection
falsepositives:
    - Unknown
level: high

```