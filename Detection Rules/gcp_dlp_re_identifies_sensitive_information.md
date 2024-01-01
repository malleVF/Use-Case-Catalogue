---
title: "Google Cloud Re-identifies Sensitive Information"
status: "test"
created: "2021/08/15"
last_modified: "2022/10/09"
tags: [impact, t1565, detection_rule]
logsrc_product: "gcp"
logsrc_service: "gcp.audit"
level: "medium"
---

## Google Cloud Re-identifies Sensitive Information

### Description

Identifies when sensitive information is re-identified in google Cloud.

```yml
title: Google Cloud Re-identifies Sensitive Information
id: 234f9f48-904b-4736-a34c-55d23919e4b7
status: test
description: Identifies when sensitive information is re-identified in google Cloud.
references:
    - https://cloud.google.com/dlp/docs/reference/rest/v2/projects.content/reidentify
author: Austin Songer @austinsonger
date: 2021/08/15
modified: 2022/10/09
tags:
    - attack.impact
    - attack.t1565
logsource:
    product: gcp
    service: gcp.audit
detection:
    selection:
        gcp.audit.method_name: projects.content.reidentify
    condition: selection
falsepositives:
    - Unknown
level: medium

```
