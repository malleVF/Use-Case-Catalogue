---
title: "Invalid PIM License"
status: "experimental"
created: "2023/09/14"
last_modified: ""
tags: [t1078, persistence, privilege_escalation, detection_rule]
logsrc_product: "azure"
logsrc_service: "pim"
level: "high"
---

## Invalid PIM License

### Description

Identifies when an organization doesn't have the proper license for PIM and is out of compliance.

```yml
title: Invalid PIM License
id: 58af08eb-f9e1-43c8-9805-3ad9b0482bd8
status: experimental
description: Identifies when an organization doesn't have the proper license for PIM and is out of compliance.
references:
    - https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-configure-security-alerts#the-organization-doesnt-have-microsoft-entra-premium-p2-or-microsoft-entra-id-governance
author: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo'
date: 2023/09/14
tags:
    - attack.t1078
    - attack.persistence
    - attack.privilege_escalation
logsource:
    product: azure
    service: pim
detection:
    selection:
        riskEventType: 'invalidLicenseAlertIncident'
    condition: selection
falsepositives:
    - Investigate if licenses have expired.
level: high

```
