---
created: 2020-02-11
last_modified: 2023-04-11
version: 2.3
tactics: Credential Access, Defense Evasion, Persistence
url: https://attack.mitre.org/techniques/T1556
platforms: Azure AD, Google Workspace, IaaS, Linux, Network, Office 365, SaaS, Windows, macOS
tags: [T1556, techniques, Credential_Access,_Defense_Evasion,_Persistence]
---

## Modify Authentication Process

### Description

Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using [Valid Accounts](https://attack.mitre.org/techniques/T1078).

Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.

### Detection

Monitor for new, unfamiliar DLL files written to a domain controller and/or local computer. Monitor for changes to Registry entries for password filters (ex: <code>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages</code>) and correlate then investigate the DLL files these files reference. 

Password filters will also show up as an autorun and loaded DLL in lsass.exe.(Citation: Clymb3r Function Hook Passwords Sept 2013)

Monitor for calls to <code>OpenProcess</code> that can be used to manipulate lsass.exe running on a domain controller as well as for malicious modifications to functions exported from authentication-related system DLLs (such as cryptdll.dll and samsrv.dll).(Citation: Dell Skeleton) 

Monitor PAM configuration and module paths (ex: <code>/etc/pam.d/</code>) for changes. Use system-integrity tools such as AIDE and monitoring tools such as auditd to monitor PAM files.

Monitor for suspicious additions to the /Library/Security/SecurityAgentPlugins directory.(Citation: Xorrior Authorization Plugins)

Configure robust, consistent account activity audit policies across the enterprise and with externally accessible services. (Citation: TechNet Audit Policy) Look for suspicious account behavior across systems that share accounts, either user, admin, or service accounts. Examples: one account logged into multiple systems simultaneously; multiple accounts logged into the same machine simultaneously; accounts logged in at odd times or outside of business hours. Activity may be from interactive login sessions or process ownership from accounts being used to execute binaries on a remote system as a particular account. Correlate other security systems with login information (e.g., a user has an active login session but has not entered the building or does not have VPN access).

Monitor property changes in Group Policy that manage authentication mechanisms (i.e. [Group Policy Modification](https://attack.mitre.org/techniques/T1484/001)). The <code>Store passwords using reversible encryption</code> configuration should be set to Disabled. Additionally, monitor and/or block suspicious command/script execution of <code>-AllowReversiblePasswordEncryption $true</code>, <code>Set-ADUser</code> and <code>Set-ADAccountControl</code>. Finally, monitor Fine-Grained Password Policies and regularly audit user accounts and group settings.(Citation: dump_pwd_dcsync)


### Defenses Bypassed



### Data Sources

  - Active Directory: Active Directory Object Modification
  -  Application Log: Application Log Content
  -  File: File Creation
  -  File: File Modification
  -  Logon Session: Logon Session Creation
  -  Module: Module Load
  -  Process: OS API Execution
  -  Process: Process Access
  -  User Account: User Account Authentication
  -  User Account: User Account Modification
  -  Windows Registry: Windows Registry Key Creation
  -  Windows Registry: Windows Registry Key Modification
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1556
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "Testing Runbooks" AND #T1556
```
