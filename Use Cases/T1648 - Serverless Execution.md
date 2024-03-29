---
created: 2022-05-27
last_modified: 2022-10-24
version: 1.0
tactics: Execution
url: https://attack.mitre.org/techniques/T1648
platforms: IaaS, Office 365, SaaS
tags: [T1648, techniques, Execution]
---

## Serverless Execution

### Description

Adversaries may abuse serverless computing, integration, and automation services to execute arbitrary code in cloud environments. Many cloud providers offer a variety of serverless resources, including compute engines, application integration services, and web servers. 

Adversaries may abuse these resources in various ways as a means of executing arbitrary commands. For example, adversaries may use serverless functions to execute malicious code, such as crypto-mining malware (i.e. [Resource Hijacking](https://attack.mitre.org/techniques/T1496)).(Citation: Cado Security Denonia) Adversaries may also create functions that enable further compromise of the cloud environment. For example, an adversary may use the `IAM:PassRole` permission in AWS or the `iam.serviceAccounts.actAs` permission in Google Cloud to add [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) to a serverless cloud function, which may then be able to perform actions the original user cannot.(Citation: Rhino Security Labs AWS Privilege Escalation)(Citation: Rhingo Security Labs GCP Privilege Escalation)

Serverless functions can also be invoked in response to cloud events (i.e. [Event Triggered Execution](https://attack.mitre.org/techniques/T1546)), potentially enabling persistent execution over time. For example, in AWS environments, an adversary may create a Lambda function that automatically adds [Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) to a user and a corresponding CloudWatch events rule that invokes that function whenever a new user is created.(Citation: Backdooring an AWS account) Similarly, an adversary may create a Power Automate workflow in Office 365 environments that forwards all emails a user receives or creates anonymous sharing links whenever a user is granted access to a document in SharePoint.(Citation: Varonis Power Automate Data Exfiltration)(Citation: Microsoft DART Case Report 001)

### Detection



### Defenses Bypassed



### Data Sources

  - Application Log: Application Log Content
  -  Cloud Service: Cloud Service Modification
### Detection Rule

```query
tag: detection_rule
tag: T1648
```

### Rule Testing

```query
tag: atomic_test
tag: T1648
```
