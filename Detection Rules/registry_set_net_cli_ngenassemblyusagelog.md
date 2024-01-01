---
title: "NET NGenAssemblyUsageLog Registry Key Tamper"
status: "experimental"
created: "2022/11/18"
last_modified: "2023/08/17"
tags: [defense_evasion, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## NET NGenAssemblyUsageLog Registry Key Tamper

### Description

Detects changes to the NGenAssemblyUsageLog registry key.
.NET Usage Log output location can be controlled by setting the NGenAssemblyUsageLog CLR configuration knob in the Registry or by configuring an environment variable (as described in the next section).
By simplify specifying an arbitrary value (e.g. fake output location or junk data) for the expected value, a Usage Log file for the .NET execution context will not be created.


```yml
title: NET NGenAssemblyUsageLog Registry Key Tamper
id: 28036918-04d3-423d-91c0-55ecf99fb892
status: experimental
description: |
  Detects changes to the NGenAssemblyUsageLog registry key.
  .NET Usage Log output location can be controlled by setting the NGenAssemblyUsageLog CLR configuration knob in the Registry or by configuring an environment variable (as described in the next section).
  By simplify specifying an arbitrary value (e.g. fake output location or junk data) for the expected value, a Usage Log file for the .NET execution context will not be created.
references:
    - https://bohops.com/2021/03/16/investigating-net-clr-usage-log-tampering-techniques-for-edr-evasion/
author: frack113
date: 2022/11/18
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|endswith: 'SOFTWARE\Microsoft\.NETFramework\NGenAssemblyUsageLog'
    condition: selection
falsepositives:
    - Unknown
level: high

```