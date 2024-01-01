---
title: "Suspicious Keyboard Layout Load"
status: "test"
created: "2019/10/12"
last_modified: "2023/08/17"
tags: [resource_development, t1588_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Suspicious Keyboard Layout Load

### Description

Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems maintained by US staff only

```yml
title: Suspicious Keyboard Layout Load
id: 34aa0252-6039-40ff-951f-939fd6ce47d8
status: test
description: Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems maintained by US staff only
references:
    - https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index
    - https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files
author: Florian Roth (Nextron Systems)
date: 2019/10/12
modified: 2023/08/17
tags:
    - attack.resource_development
    - attack.t1588.002
logsource:
    category: registry_set
    product: windows
    definition: 'Requirements: Sysmon config that monitors \Keyboard Layout\Preload subkey of the HKLU hives - see https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files'
detection:
    selection_registry:
        TargetObject|contains:
            - '\Keyboard Layout\Preload\'
            - '\Keyboard Layout\Substitutes\'
        Details|contains:
            - 00000429  # Persian (Iran)
            - 00050429  # Persian (Iran)
            - 0000042a  # Vietnamese
    condition: selection_registry
falsepositives:
    - Administrators or users that actually use the selected keyboard layouts (heavily depends on the organisation's user base)
level: medium

```