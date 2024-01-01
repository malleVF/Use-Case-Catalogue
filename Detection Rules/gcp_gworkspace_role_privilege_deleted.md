---
title: "Google Workspace Role Privilege Deleted"
status: "test"
created: "2021/08/24"
last_modified: "2023/10/11"
tags: [impact, detection_rule]
logsrc_product: "gcp"
logsrc_service: "google_workspace.admin"
level: "medium"
---

## Google Workspace Role Privilege Deleted

### Description

Detects when an a role privilege is deleted in Google Workspace.

```yml
title: Google Workspace Role Privilege Deleted
id: bf638ef7-4d2d-44bb-a1dc-a238252e6267
status: test
description: Detects when an a role privilege is deleted in Google Workspace.
references:
    - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging#3
    - https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-delegated-admin-settings
author: Austin Songer
date: 2021/08/24
modified: 2023/10/11
tags:
    - attack.impact
logsource:
    product: gcp
    service: google_workspace.admin
detection:
    selection:
        eventService: admin.googleapis.com
        eventName: REMOVE_PRIVILEGE
    condition: selection
falsepositives:
    - Unknown

level: medium

```
