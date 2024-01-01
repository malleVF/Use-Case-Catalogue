---
title: "Google Workspace User Granted Admin Privileges"
status: "test"
created: "2021/08/23"
last_modified: "2023/10/11"
tags: [persistence, t1098, detection_rule]
logsrc_product: "gcp"
logsrc_service: "google_workspace.admin"
level: "medium"
---

## Google Workspace User Granted Admin Privileges

### Description

Detects when an Google Workspace user is granted admin privileges.

```yml
title: Google Workspace User Granted Admin Privileges
id: 2d1b83e4-17c6-4896-a37b-29140b40a788
status: test
description: Detects when an Google Workspace user is granted admin privileges.
references:
    - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
    - https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-user-settings#GRANT_ADMIN_PRIVILEGE
author: Austin Songer
date: 2021/08/23
modified: 2023/10/11
tags:
    - attack.persistence
    - attack.t1098
logsource:
    product: gcp
    service: google_workspace.admin
detection:
    selection:
        eventService: admin.googleapis.com
        eventName:
            - GRANT_DELEGATED_ADMIN_PRIVILEGES
            - GRANT_ADMIN_PRIVILEGE
    condition: selection
falsepositives:
    - Google Workspace admin role privileges, may be modified by system administrators.
level: medium

```