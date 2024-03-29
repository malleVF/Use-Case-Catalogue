---
title: "Tomcat WebServer Logs Deleted"
status: "experimental"
created: "2023/02/16"
last_modified: ""
tags: [defense_evasion, t1070, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "medium"
---

## Tomcat WebServer Logs Deleted

### Description

Detects the deletion of tomcat WebServer logs which may indicate an attempt to destroy forensic evidence

```yml
title: Tomcat WebServer Logs Deleted
id: 270185ff-5f50-4d6d-a27f-24c3b8c9fef8
status: experimental
description: Detects the deletion of tomcat WebServer logs which may indicate an attempt to destroy forensic evidence
references:
    - Internal Research
    - https://linuxhint.com/view-tomcat-logs-windows/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023/02/16
tags:
    - attack.defense_evasion
    - attack.t1070
logsource:
    category: file_delete
    product: windows
detection:
    selection:
        TargetFilename|contains|all:
            - '\Tomcat'
            - '\logs\'
        TargetFilename|contains:
            - 'catalina.'
            - '_access_log.'
            - 'localhost.'
    condition: selection
falsepositives:
    - During uninstallation of the tomcat server
    - During log rotation
level: medium

```
