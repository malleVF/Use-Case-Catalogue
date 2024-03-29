---
title: "Github New Secret Created"
status: "test"
created: "2023/01/20"
last_modified: ""
tags: [defense_evasion, persistence, privilege_escalation, initial_access, t1078_004, detection_rule]
logsrc_product: "github"
logsrc_service: "audit"
level: "low"
---

## Github New Secret Created

### Description

Detects when a user creates action secret for the organization, environment, codespaces or repository.

```yml
title: Github New Secret Created
id: f9405037-bc97-4eb7-baba-167dad399b83
status: test
description: Detects when a user creates action secret for the organization, environment, codespaces or repository.
author: Muhammad Faisal
date: 2023/01/20
references:
    - https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization#audit-log-actions
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.privilege_escalation
    - attack.initial_access
    - attack.t1078.004
logsource:
    product: github
    service: audit
    definition: 'Requirements: The audit log streaming feature must be enabled to be able to receive such logs. You can enable following the documentation here: https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-audit-log-streaming'
detection:
    selection:
        action:
            - 'org.create_actions_secret'
            - 'environment.create_actions_secret'
            - 'codespaces.create_an_org_secret'
            - 'repo.create_actions_secret'
    condition: selection
fields:
    - 'action'
    - 'actor'
    - 'org'
    - 'actor_location.country_code'
falsepositives:
    - This detection cloud be noisy depending on the environment. It is recommended to keep a check on the new secrets when created and validate the "actor".
level: low

```
