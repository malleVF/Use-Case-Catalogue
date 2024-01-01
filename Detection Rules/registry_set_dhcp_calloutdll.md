---
title: "DHCP Callout DLL Installation"
status: "test"
created: "2017/05/15"
last_modified: "2023/08/17"
tags: [defense_evasion, t1574_002, t1112, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## DHCP Callout DLL Installation

### Description

Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required)

```yml
title: DHCP Callout DLL Installation
id: 9d3436ef-9476-4c43-acca-90ce06bdf33a
status: test
description: Detects the installation of a Callout DLL via CalloutDlls and CalloutEnabled parameter in Registry, which can be used to execute code in context of the DHCP server (restart required)
references:
    - https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html
    - https://technet.microsoft.com/en-us/library/cc726884(v=ws.10).aspx
    - https://msdn.microsoft.com/de-de/library/windows/desktop/aa363389(v=vs.85).aspx
author: Dimitrios Slamaris
date: 2017/05/15
modified: 2023/08/17
tags:
    - attack.defense_evasion
    - attack.t1574.002
    - attack.t1112
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|endswith:
            - '\Services\DHCPServer\Parameters\CalloutDlls'
            - '\Services\DHCPServer\Parameters\CalloutEnabled'
    condition: selection
falsepositives:
    - Unknown
level: high

```