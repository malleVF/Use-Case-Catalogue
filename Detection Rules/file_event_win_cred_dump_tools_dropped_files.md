---
title: "Cred Dump Tools Dropped Files"
status: "test"
created: "2019/11/01"
last_modified: "2022/09/21"
tags: [credential_access, t1003_001, t1003_002, t1003_003, t1003_004, t1003_005, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Cred Dump Tools Dropped Files

### Description

Files with well-known filenames (parts of credential dump software or files produced by them) creation

```yml
title: Cred Dump Tools Dropped Files
id: 8fbf3271-1ef6-4e94-8210-03c2317947f6
status: test
description: Files with well-known filenames (parts of credential dump software or files produced by them) creation
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
author: Teymur Kheirkhabarov, oscd.community
date: 2019/11/01
modified: 2022/09/21
tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.t1003.002
    - attack.t1003.003
    - attack.t1003.004
    - attack.t1003.005
logsource:
    category: file_event
    product: windows
detection:
    selection:
        - TargetFilename|contains:
              - '\fgdump-log'
              - '\kirbi'
              - '\pwdump'
              - '\pwhashes'
              - '\wce_ccache'
              - '\wce_krbtkts'
        - TargetFilename|endswith:
              - '\cachedump.exe'
              - '\cachedump64.exe'
              - '\DumpExt.dll'
              - '\DumpSvc.exe'
              - '\Dumpy.exe'
              - '\fgexec.exe'
              - '\lsremora.dll'
              - '\lsremora64.dll'
              - '\NTDS.out'
              - '\procdump64.exe'
              - '\pstgdump.exe'
              - '\pwdump.exe'
              - '\SAM.out'
              - '\SECURITY.out'
              - '\servpw.exe'
              - '\servpw64.exe'
              - '\SYSTEM.out'
              - '\test.pwd'
              - '\wceaux.dll'
    condition: selection
falsepositives:
    - Legitimate Administrator using tool for password recovery
level: high

```