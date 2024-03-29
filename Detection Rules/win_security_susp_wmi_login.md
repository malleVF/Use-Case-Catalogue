---
title: "Login with WMI"
status: "stable"
created: "2019/12/04"
last_modified: ""
tags: [execution, t1047, detection_rule]
logsrc_product: "windows"
logsrc_service: "security"
level: "low"
---

## Login with WMI

### Description

Detection of logins performed with WMI

```yml
title: Login with WMI
id: 5af54681-df95-4c26-854f-2565e13cfab0
status: stable
description: Detection of logins performed with WMI
author: Thomas Patzke
date: 2019/12/04
tags:
    - attack.execution
    - attack.t1047
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        ProcessName|endswith: '\WmiPrvSE.exe'
    condition: selection
falsepositives:
    - Monitoring tools
    - Legitimate system administration
level: low

```
