---
title: "Suspicious Windows Service Tampering"
status: "experimental"
created: "2022/09/01"
last_modified: "2023/08/07"
tags: [defense_evasion, t1489, detection_rule]
logsrc_product: "windows"
logsrc_service: ""
level: "high"
---

## Suspicious Windows Service Tampering

### Description

Detects the usage of binaries such as 'net', 'sc' or 'powershell' in order to stop, pause or delete critical or important Windows services such as AV, Backup, etc. As seen being used in some ransomware scripts

```yml
title: Suspicious Windows Service Tampering
id: ce72ef99-22f1-43d4-8695-419dcb5d9330
related:
    - id: eb87818d-db5d-49cc-a987-d5da331fbd90
      type: derived
    - id: 6783aa9e-0dc3-49d4-a94a-8b39c5fd700b
      type: obsoletes
    - id: 7fd4bb39-12d0-45ab-bb36-cebabc73dc7b
      type: obsoletes
status: experimental
description: Detects the usage of binaries such as 'net', 'sc' or 'powershell' in order to stop, pause or delete critical or important Windows services such as AV, Backup, etc. As seen being used in some ransomware scripts
references:
    - https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/h/ransomware-actor-abuses-genshin-impact-anti-cheat-driver-to-kill-antivirus/Genshin%20Impact%20Figure%2010.jpg
    - https://www.trellix.com/en-sg/about/newsroom/stories/threat-labs/lockergoga-ransomware-family-used-in-targeted-attacks.html
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
    - https://research.nccgroup.com/2022/08/19/back-in-black-unlocking-a-lockbit-3-0-ransomware-attack/
    - https://www.virustotal.com/gui/file/38283b775552da8981452941ea74191aa0d203edd3f61fb2dee7b0aea3514955
author: Nasreddine Bencherchali (Nextron Systems), frack113
date: 2022/09/01
modified: 2023/08/07
tags:
    - attack.defense_evasion
    - attack.t1489
logsource:
    category: process_creation
    product: windows
detection:
    selection_net_img:
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
    selection_net_cli:
        CommandLine|contains: ' stop '
    selection_sc_img:
        - OriginalFileName: 'sc.exe'
        - Image|endswith: '\sc.exe'
    selection_sc_cli:
        CommandLine|contains:
            - ' stop '
            - ' delete '
            - ' pause '
    selection_pwsh_img:
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
    selection_pwsh_cli:
        CommandLine|contains:
            - 'Stop-Service '
            - 'Remove-Service '
    selection_services:
        CommandLine|contains:
            - '143Svc'
            - 'Acronis VSS Provider'
            - 'AcronisAgent'
            - 'AcrSch2Svc'
            - 'Antivirus'
            - 'ARSM'
            - 'aswBcc'
            - 'Avast Business Console Client Antivirus Service'
            - 'avast! Antivirus'
            - 'AVG Antivirus'
            - 'avgAdminClient'
            - 'AvgAdminServer'
            - 'AVP1' # Covers multiple AVP versions
            - 'BackupExec'
            - 'bedbg'
            - 'BITS'
            - 'BrokerInfrastructure'
            - 'Client Agent 7.60'
            - 'Core Browsing Protection'
            - 'Core Mail Protection'
            - 'Core Scanning Server' # Covers 'Core Scanning ServerEx'
            - 'DCAgent'
            - 'EhttpSr' # Covers 'EhttpSry', 'EhttpSrv'
            - 'ekrn' # Covers 'ekrnEpsw'
            - 'Enterprise Client Service'
            - 'epag'
            - 'EPIntegrationService'
            - 'EPProtectedService'
            - 'EPRedline'
            - 'EPSecurityService'
            - 'EPUpdateService'
            - 'EraserSvc11710'
            - 'EsgShKernel'
            - 'ESHASRV'
            - 'FA_Scheduler'
            - 'FirebirdGuardianDefaultInstance'
            - 'FirebirdServerDefaultInstance'
            - 'HealthTLService'
            - 'MSSQLFDLauncher$' # Covers 'SHAREPOINT', 'TPS', 'SBSMonitoring', etc.
            - 'hmpalertsvc'
            - 'HMS'
            - 'IISAdmin'
            - 'IMANSVC'
            - 'IMAP4Svc'
            - 'KAVFS'
            - 'KAVFSGT'
            - 'kavfsslp'
            - 'klbackupdisk'
            - 'klbackupflt'
            - 'klflt'
            - 'klhk'
            - 'KLIF'
            - 'klim6'
            - 'klkbdflt'
            - 'klmouflt'
            - 'klnagent'
            - 'klpd'
            - 'kltap'
            - 'KSDE1.0.0'
            - 'LogProcessorService'
            - 'M8EndpointAgent'
            - 'macmnsvc'
            - 'masvc'
            - 'MBAMService'
            - 'MBCloudEA'
            - 'MBEndpointAgent'
            - 'McAfeeDLPAgentService'
            - 'McAfeeEngineService'
            - 'MCAFEEEVENTPARSERSRV'
            - 'McAfeeFramework'
            - 'MCAFEETOMCATSRV530'
            - 'McShield'
            - 'McTaskManager'
            - 'mfefire'
            - 'mfemms'
            - 'mfevto'
            - 'mfevtp'
            - 'mfewc'
            - 'MMS'
            - 'mozyprobackup'
            - 'MsDtsServer'
            - 'MSExchange'
            - 'msftesq1SPROO'
            - 'msftesql$PROD'
            - 'MSOLAP$SQL_2008'
            - 'MSOLAP$SYSTEM_BGC'
            - 'MSOLAP$TPS'
            - 'MSOLAP$TPSAMA'
            - 'MSOLAPSTPS'
            - 'MSOLAPSTPSAMA'
            - 'mssecflt'
            - 'MSSQ!I.SPROFXENGAGEMEHT'
            - 'MSSQ0SHAREPOINT'
            - 'MSSQ0SOPHOS'
            - 'MSSQL'
            - 'MySQL'
            - 'NanoServiceMain'
            - 'NetMsmqActivator'
            - 'ntrtscan'
            - 'ofcservice'
            - 'Online Protection System'
            - 'OracleClientCache80'
            - 'PandaAetherAgent'
            - 'PccNTUpd'
            - 'PDVFSService'
            - 'POP3Svc'
            - 'POVFSService'
            - 'PSUAService'
            - 'Quick Update Service'
            - 'RepairService'
            - 'ReportServer'
            - 'ReportServer$'
            - 'RESvc'
            - 'RpcEptMapper'
            - 'sacsvr'
            - 'SamSs'
            - 'SAVAdminService'
            - 'SAVService'
            - 'ScSecSvc'
            - 'SDRSVC'
            - 'sense'
            - 'SentinelAgent'
            - 'SentinelHelperService'
            - 'SepMasterService'
            - 'ShMonitor'
            - 'Smcinst'
            - 'SmcService'
            - 'SMTPSvc'
            - 'SNAC'
            - 'SntpService'
            - 'Sophos'
            - 'SQ1SafeOLRService'
            - 'SQL Backups'
            - 'SQL Server'
            - 'SQLAgent'
            - 'SQLBrowser'
            - 'SQLsafe'
            - 'SQLSERVERAGENT'
            - 'SQLTELEMETRY'
            - 'SQLWriter'
            - 'SSISTELEMETRY130'
            - 'SstpSvc'
            - 'svcGenericHost'
            - 'swc_service'
            - 'swi_filter'
            - 'swi_service'
            - 'swi_update'
            - 'Symantec'
            - 'Telemetryserver'
            - 'ThreatLockerService'
            - 'TMBMServer'
            - 'TmCCSF'
            - 'TmFilter'
            - 'TMiCRCScanService'
            - 'tmlisten'
            - 'TMLWCSService'
            - 'TmPfw'
            - 'TmPreFilter'
            - 'TmProxy'
            - 'TMSmartRelayService'
            - 'tmusa'
            - 'Trend Micro Deep Security Manager'
            - 'TrueKey'
            - 'UI0Detect'
            - 'UTODetect'
            - 'Veeam'
            - 'VeeamDeploySvc'
            - 'Veritas System Recovery'
            - 'VSApiNt'
            - 'VSS'
            - 'W3Svc'
            - 'wbengine'
            - 'WdNisSvc'
            - 'WeanClOudSve'
            - 'Weems JY'
            - 'WinDefend'
            - 'wozyprobackup'
            - 'WRSVC'
            - 'Zoolz 2 Service'
    condition: selection_services and (all of selection_net_* or all of selection_pwsh_* or all of selection_sc_*)
falsepositives:
    - Administrators or tools shutting down the services due to upgrade or removal purposes. If you experience some false positive, please consider adding filters to the parent process launching this command and not removing the entry
level: high

```