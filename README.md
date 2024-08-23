# Release Information 

- **Version**: 1.0.0 
- **Certified**: No 
- **Publisher**: Fortinet 
- **Compatible Version**: FortiSOAR 7.4.0 and later 

# Overview 

Cyber threat actors target Jenkins Arbitrary File Read vulnerability (CVE-2024-23897) in ransomware attacks. FortiGuard Labs continues to see active attack telemetry targeting the vulnerability. 

 The **Outbreak Response - Jenkins RCE Attack** solution pack works with the Threat Hunt rules in [Outbreak Response Framework](https://github.com/fortinet-fortisoar/solution-pack-outbreak-response-framework/blob/release/1.1.0/README.md#threat-hunt-rules) solution pack to conduct hunts that identify and help investigate potential Indicators of Compromise (IOCs) associated with this vulnerability within operational environments of *FortiSIEM*, *FortiAnalyzer*, *QRadar*, *Splunk*, and *Azure Log Analytics*.

 The [FortiGuard Outbreak Page](https://www.fortiguard.com/outbreak-alert/jenkins-rce) contains information about the outbreak alert **Outbreak Response - Jenkins RCE Attack**. 

## Background: 

Jenkins is an open-source continuous integration (CI) server and a popular DevOps tool used by thousands of development teams. It manages and controls several stages of the software delivery process, including building, automated testing, packaging, and more. 

Jenkins has a built-in Command-Line Interface (CLI) that uses the args4j library to parse command arguments and options on the Jenkins controller during CLI command processing. The vulnerability (CVE-2024-23897) in this library allows unauthenticated users to read the initial lines of any file on the file system, which further leads to RCE. 

Additionally, FortiRecon ACI service has observed recent discussions related to CVE-2024-23897 on the Dark Web. Also, a Proof of Concept (PoC) exploit has been made publicly available which makes this vulnerability crucial for patching and detecting any exploitation activity. 

## Announced: 

Fortinet customers remain protected through the IPS service and has blocked all the known hashes and Indicators of Compromise (IoCs) in the related campagins. FortiGuard Labs advises organizations to apply the latest Jenkins security updates and patches to fully mitigate any risks.
 

## Latest Developments: 

August 1, 2024: CloudSEK's threat research team has uncovered a ransomware attack disrupting banking system in India, targeting banks and payment providers.
https://www.cloudsek.com/blog/major-payment-disruption-ransomware-strikes-indian-banking-infrastructure

July 23, 2024: IntelBroker Threat Actor exploited Jenkins vulnerability to exfiltrate sensitive data, impacting multiple clients.
https://www.cloudsek.com/blog/born-group-supply-chain-breach-in-depth-analysis-of-intelbrokers-jenkins-exploitation

March 12, 2024: FortiGuard Labs released the Threat Signal Report on CVE-2024-23897.
https://www.fortiguard.com/threat-signal-report/5401/jenkins-arbitrary-file-read-vulnerability-cve-2024-23897

January 24, 2024: Jenkins released a security advisory about the vulnerability.
https://www.jenkins.io/security/advisory/2024-01-24/ 

# Next Steps
 | [Installation](./docs/setup.md#installation) | [Configuration](./docs/setup.md#configuration) | [Usage](./docs/usage.md) | [Contents](./docs/contents.md) | 
 |--------------------------------------------|----------------------------------------------|------------------------|------------------------------|