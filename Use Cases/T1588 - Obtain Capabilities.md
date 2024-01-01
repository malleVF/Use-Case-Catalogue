---
created: 2020-10-01
last_modified: 2021-10-18
version: 1.1
tactics: Resource Development
url: https://attack.mitre.org/techniques/T1588
platforms: PRE
tags: [T1588, techniques, Resource_Development]
---

## Obtain Capabilities

### Description

Adversaries may buy and/or steal capabilities that can be used during targeting. Rather than developing their own capabilities in-house, adversaries may purchase, freely download, or steal them. Activities may include the acquisition of malware, software (including licenses), exploits, certificates, and information relating to vulnerabilities. Adversaries may obtain capabilities to support their operations throughout numerous phases of the adversary lifecycle.

In addition to downloading free malware, software, and exploits from the internet, adversaries may purchase these capabilities from third-party entities. Third-party entities can include technology companies that specialize in malware and exploits, criminal marketplaces, or from individuals.(Citation: NationsBuying)(Citation: PegasusCitizenLab)

In addition to purchasing capabilities, adversaries may steal capabilities from third-party entities (including other adversaries). This can include stealing software licenses, malware, SSL/TLS and code-signing certificates, or raiding closed databases of vulnerabilities or exploits.(Citation: DiginotarCompromise)

### Detection

Consider analyzing malware for features that may be associated with malware providers, such as compiler used, debugging artifacts, code similarities, or even group identifiers associated with specific Malware-as-a-Service (MaaS) offerings. Malware repositories can also be used to identify additional samples associated with the developers and the adversary utilizing their services. Identifying overlaps in malware use by different adversaries may indicate malware was obtained by the adversary rather than developed by them. In some cases, identifying overlapping characteristics in malware used by different adversaries may point to a shared quartermaster.(Citation: FireEyeSupplyChain) Malware repositories can also be used to identify features of tool use associated with an adversary, such as watermarks in [Cobalt Strike](https://attack.mitre.org/software/S0154) payloads.(Citation: Analyzing CS Dec 2020)

Consider use of services that may aid in the tracking of newly issued certificates and/or certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary infrastructure.(Citation: Splunk Kovar Certificates 2017) Some server-side components of adversary tools may have default values set for SSL/TLS certificates.(Citation: Recorded Future Beacon Certificates)

Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Defense Evasion or Command and Control.

### Defenses Bypassed



### Data Sources

  - Certificate: Certificate Registration
  -  Internet Scan: Response Content
  -  Malware Repository: Malware Content
  -  Malware Repository: Malware Metadata
### Detection Rule

```dataview
table without id
file.link AS "Name",
status AS "Status",
level AS "Level",
logsrc_product AS "Log Source Product"
FROM "Detection Rules" AND #T1588
```

### Rule Testing

```dataview
TABLE without id
filename AS "Name"
FROM "atomics" AND #T1588
```
