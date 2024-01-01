---
title: "Linux Keylogging with Pam.d"
status: "test"
created: "2021/05/24"
last_modified: "2022/12/18"
tags: [credential_access, t1003, t1056_001, detection_rule]
logsrc_product: "linux"
logsrc_service: "auditd"
level: "high"
---

## Linux Keylogging with Pam.d

### Description

Detect attempt to enable auditing of TTY input

```yml
title: Linux Keylogging with Pam.d
id: 49aae26c-450e-448b-911d-b3c13d178dfc
status: test
description: Detect attempt to enable auditing of TTY input
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1056.001/T1056.001.md
    - https://linux.die.net/man/8/pam_tty_audit
    - https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-configuring_pam_for_auditing
    - https://access.redhat.com/articles/4409591#audit-record-types-2
author: 'Pawel Mazur'
date: 2021/05/24
modified: 2022/12/18
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1056.001
logsource:
    product: linux
    service: auditd
detection:
    selection_path_events:
        type: PATH
        name:
            - '/etc/pam.d/system-auth'
            - '/etc/pam.d/password-auth'
    selection_tty_events:
        type:
            - 'TTY'
            - 'USER_TTY'
    condition: 1 of selection_*
falsepositives:
    - Administrative work
level: high

```
