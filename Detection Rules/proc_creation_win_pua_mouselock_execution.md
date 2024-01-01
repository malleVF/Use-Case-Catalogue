---
title: "PUA - Mouse Lock Execution"
status: "test"
created: "2020/08/13"
last_modified: "2023/02/21"
tags: [credential_access, collection, t1056_002, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## PUA - Mouse Lock Execution

### Description

In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool "Mouse Lock" as being used for both credential access and collection in security incidents.

```yml
title: PUA - Mouse Lock Execution
id: c9192ad9-75e5-43eb-8647-82a0a5b493e3
status: test
description: In Kaspersky's 2020 Incident Response Analyst Report they listed legitimate tool "Mouse Lock" as being used for both credential access and collection in security incidents.
references:
    - https://github.com/klsecservices/Publications/blob/657deb6a6eb6e00669afd40173f425fb49682eaa/Incident-Response-Analyst-Report-2020.pdf
    - https://sourceforge.net/projects/mouselock/
author: Cian Heasley
date: 2020/08/13
modified: 2023/02/21
tags:
    - attack.credential_access
    - attack.collection
    - attack.t1056.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        - Product|contains: 'Mouse Lock'
        - Company|contains: 'Misc314'
        - CommandLine|contains: 'Mouse Lock_'
    condition: selection
fields:
    - Product
    - Company
    - CommandLine
falsepositives:
    - Legitimate uses of Mouse Lock software
level: medium

```