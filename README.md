## home-network-security-assessment
Authorized home network security assessment — identified CVE-2017-8798 (CVSS 9.8) on an internet-facing UPnP service. Documented Nmap methodology and deployed custom Suricata rules to monitor port 1900 traffic in Security Onion.

## Overview 
This repository contains a detailed account on the steps and procedures used to find multiple vulnerabilities and secure a home network. Upon verbal authorization from the network owner, I began reconnaissance on the local subnet. A scan revealed multiple CVEs — CVE-2017-8798, which scored highest for severity, was on a port completely accessible to anyone on the internet. Security Onion and Suricata with custom rules were deployed in response to monitor network traffic. An analysis of logs concluded no unauthorized or malicious activity.

## Authorization and Rules of Engagement
All testing was done with prior knowledge and verbal consent of the network owner. The scope consisted of the home network subnet and router. Any destructive testing and exploitation of vulnerabilities was off limits.

## Tools Used 
- Nmap — Network and vulnerability scanning
- Kali Linux — Pen Testing OS
- Security Onion — Network monitoring OS
- Suricata — Intrusion detection and custom rule implementation
- Zeek — Network Traffic analysis and logging

## Findings Summary 
The primary finding is MiniUPnP 1.8 running on port 1900 while being WAN facing.
All associated CVEs and CVSS scores:
- CVE-2017-8798(most severe) — 9.8 CRITICAL
- CVE-2017-1000494 — 7.8 HIGH
- CVE-2019-12111 — 7.5 HIGH
- CVE-2019-12109 — 7.5 HIGH
- CVE-2019-12108 — 7.5 HIGH 
- CVE-2013-2600 — 7.5 HIGH 
- CVE-2026-5720 — 7.1 HIGH

## Findings Note 
CVE-2026-5720 differs from the other findings — its CVSS vector specifies an adjacent attack vector (AV:A), meaning exploitation requires local network access rather than internet exposure. It is included for completeness as it affects the same miniupnpd service, but does not carry the same external-exposure risk as CVE-2017-8798.

## Repository Structure

```
home-network-security-assessment/
├── README.md
├── 01-methodology/
│   ├── 01_nmap_recon.md
│   └── 02_security_onion_monitoring.md
├── 02-findings/
│   └── cve-2017-8798_miniupnp.md
├── 03-evidence/
│   ├── hunt_query.txt
│   ├── nmap_output_redacted.txt
│   └── suricata_rule.txt
└── 04-remediation/
    └── notes.md
```
