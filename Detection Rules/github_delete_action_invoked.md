---
title: "Github Delete Action Invoked"
status: "test"
created: "2023/01/19"
last_modified: ""
tags: [impact, collection, t1213_003, detection_rule]
logsrc_product: "github"
logsrc_service: "audit"
level: "medium"
---

## Github Delete Action Invoked

### Description

Detects delete action in the Github audit logs for codespaces, environment, project and repo.

```yml
title: Github Delete Action Invoked
id: 16a71777-0b2e-4db7-9888-9d59cb75200b
status: test
description: Detects delete action in the Github audit logs for codespaces, environment, project and repo.
author: Muhammad Faisal
date: 2023/01/19
references:
    - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#audit-log-actions
tags:
    - attack.impact
    - attack.collection
    - attack.t1213.003
logsource:
    product: github
    service: audit
    definition: 'Requirements: The audit log streaming feature must be enabled to be able to receive such logs. You can enable following the documentation here: https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-audit-log-streaming'
detection:
    selection:
        action:
            - 'codespaces.delete'
            - 'environment.delete'
            - 'project.delete'
            - 'repo.destroy'
    condition: selection
fields:
    - 'action'
    - 'actor'
    - 'org'
    - 'actor_location.country_code'
falsepositives:
    - Validate the deletion activity is permitted. The "actor" field need to be validated.
level: medium

```
