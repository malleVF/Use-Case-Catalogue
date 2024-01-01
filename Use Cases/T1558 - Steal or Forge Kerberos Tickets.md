---
created: 2020-02-11
last_modified: 2023-03-30
version: 1.4
tactics: Credential Access
url: https://attack.mitre.org/techniques/T1558
platforms: Linux, Windows, macOS
tags: [T1558, techniques, Credential_Access]
---

## Steal or Forge Kerberos Tickets

### Description

Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003). Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as ?realms?, there are three basic participants: client, service, and Key Distribution Center (KDC).(Citation: ADSecurity Kerberos Ring Decoder) Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting.  Adversaries may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access.

On Windows, the built-in <code>klist</code> utility can be used to list and analyze cached Kerberos tickets.(Citation: Microsoft Klist)

Linux systems on Active Directory domains store Kerberos credentials locally in the credential cache file referred to as the "ccache". The credentials are stored in the ccache file while they remain valid and generally while a user's session lasts.(Citation: MIT ccache) On modern Redhat Enterprise Linux systems, and derivative distributions, the System Security Services Daemon (SSSD) handles Kerberos tickets. By default SSSD maintains a copy of the ticket database that can be found in <code>/var/lib/sss/secrets/secrets.ldb</code> as well as the corresponding key located in <code>/var/lib/sss/secrets/.secrets.mkey</code>. Both files require root access to read. If an adversary is able to access the database and key, the credential cache Kerberos blob can be extracted and converted into a usable Kerberos ccache file that adversaries may use for [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003). The ccache file may also be converted into a Windows format using tools such as Kekeo.(Citation: Linux Kerberos Tickets)(Citation: Brining MimiKatz to Unix)(Citation: Kekeo)


Kerberos tickets on macOS are stored in a standard ccache format, similar to Linux. By default, access to these ccache entries is federated through the KCM daemon process via the Mach RPC protocol, which uses the caller's environment to determine access. The storage location for these ccache entries is influenced by the <code>/etc/krb5.conf</code> configuration file and the <code>KRB5CCNAME</code> environment variable which can specify to save them to disk or keep them protected via the KCM daemon. Users can interact with ticket storage using <code>kinit</code>, <code>klist</code>, <code>ktutil</code>, and <code>kcc</code> built-in binaries or via Apple's native Kerberos framework. Adversaries can use open source tools to interact with the ccache files directly or to use the Kerberos framework to call lower-level APIs for extracting the user's TGT or Service Tickets.(Citation: SpectorOps Bifrost Kerberos macOS 2019)(Citation: macOS kerberos framework MIT)


### Detection

Monitor for anomalous Kerberos activity, such as malformed or blank fields in Windows logon/logoff events (Event ID 4624, 4672, 4634), RC4 encryption within ticket granting tickets (TGTs), and ticket granting service (TGS) requests without preceding TGT requests.(Citation: ADSecurity Detecting Forged Tickets)(Citation: Stealthbits Detect PtT 2019)(Citation: CERT-EU Golden Ticket Protection)

Monitor the lifetime of TGT tickets for values that differ from the default domain duration.(Citation: Microsoft Kerberos Golden Ticket)

Monitor for indications of [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) being used to move laterally. 

Enable Audit Kerberos Service Ticket Operations to log Kerberos TGS service ticket requests. Particularly investigate irregular patterns of activity (ex: accounts making numerous requests, Event ID 4769, within a small time frame, especially if they also request RC4 encryption [Type 0x17]).(Citation: Microsoft Detecting Kerberoasting Feb 2018) (Citation: AdSecurity Cracking Kerberos Dec 2015)

Monitor for unexpected processes interacting with lsass.exe.(Citation: Medium Detecting Attempts to Steal Passwords from Memory) Common credential dumpers such as [Mimikatz](https://attack.mitre.org/software/S0002) access the LSA Subsystem Service (LSASS) process by opening the process, locating the LSA secrets key, and decrypting the sections in memory where credential details, including Kerberos tickets, are stored.

Monitor for unusual processes accessingÿ<code>secrets.ldb</code> and <code>.secrets.mkey</code> located in <code>/var/lib/sss/secrets/</code>.

### Defenses Bypassed



### Data Sources

  - Active Directory: Active Directory Credential Request
  -  Command: Command Execution
  -  File: File Access
  -  Logon Session: Logon Session Metadata
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1558
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1558
```
