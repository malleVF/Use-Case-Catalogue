---
title: "Copying Sensitive Files with Credential Data"
status: "test"
created: "2019/10/22"
last_modified: "2022/11/11"
tags: [credential_access, t1003_002, t1003_003, car_2013-07-001, s0404, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Copying Sensitive Files with Credential Data

### Description

Files with well-known filenames (sensitive files with credential data) copying

```yml
title: Copying Sensitive Files with Credential Data
id: e7be6119-fc37-43f0-ad4f-1f3f99be2f9f
status: test
description: Files with well-known filenames (sensitive files with credential data) copying
references:
    - https://room362.com/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/
author: Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
date: 2019/10/22
modified: 2022/11/11
tags:
    - attack.credential_access
    - attack.t1003.002
    - attack.t1003.003
    - car.2013-07-001
    - attack.s0404
logsource:
    category: process_creation
    product: windows
detection:
    selection_esent_img:
        - Image|endswith: '\esentutl.exe'
        - OriginalFileName: '\esentutl.exe'
    selection_esent_cli:
        CommandLine|contains:
            - 'vss'
            - ' /m '
            - ' /y '
    selection_susp_paths:
        CommandLine|contains:
            - '\windows\ntds\ntds.dit'
            - '\config\sam'
            - '\config\security'
            - '\config\system '        # space needed to avoid false positives with \config\systemprofile\
            - '\repair\sam'
            - '\repair\system'
            - '\repair\security'
            - '\config\RegBack\sam'
            - '\config\RegBack\system'
            - '\config\RegBack\security'
    condition: all of selection_esent_* or selection_susp_paths
falsepositives:
    - Copying sensitive files for legitimate use (eg. backup) or forensic investigation by legitimate incident responder or forensic invetigator
level: high

```