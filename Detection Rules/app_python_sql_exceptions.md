---
title: "Python SQL Exceptions"
status: "stable"
created: "2017/08/12"
last_modified: "2020/09/01"
tags: [initial_access, t1190, detection_rule]
logsrc_product: "python"
logsrc_service: ""
level: "medium"
---

## Python SQL Exceptions

### Description

Generic rule for SQL exceptions in Python according to PEP 249

```yml
title: Python SQL Exceptions
id: 19aefed0-ffd4-47dc-a7fc-f8b1425e84f9
status: stable
description: Generic rule for SQL exceptions in Python according to PEP 249
references:
    - https://www.python.org/dev/peps/pep-0249/#exceptions
author: Thomas Patzke
date: 2017/08/12
modified: 2020/09/01
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: application
    product: python
detection:
    keywords:
        - DataError
        - IntegrityError
        - ProgrammingError
        - OperationalError
    condition: keywords
falsepositives:
    - Application bugs
level: medium

```