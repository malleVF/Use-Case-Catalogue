---
title: "Google Cloud SQL Database Modified or Deleted"
status: "test"
created: "2021/10/15"
last_modified: "2022/12/25"
tags: [impact, detection_rule]
logsrc_product: "gcp"
logsrc_service: "gcp.audit"
level: "medium"
---

## Google Cloud SQL Database Modified or Deleted

### Description

Detect when a Cloud SQL DB has been modified or deleted.

```yml
title: Google Cloud SQL Database Modified or Deleted
id: f346bbd5-2c4e-4789-a221-72de7685090d
status: test
description: Detect when a Cloud SQL DB has been modified or deleted.
references:
    - https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/users/update
author: Austin Songer @austinsonger
date: 2021/10/15
modified: 2022/12/25
tags:
    - attack.impact
logsource:
    product: gcp
    service: gcp.audit
detection:
    selection:
        gcp.audit.method_name:
            - cloudsql.instances.create
            - cloudsql.instances.delete
            - cloudsql.users.update
            - cloudsql.users.delete
    condition: selection
falsepositives:
    - SQL Database being modified or deleted may be performed by a system administrator.
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - SQL Database modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: medium

```