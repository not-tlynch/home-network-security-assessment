# home-network-security-assessment

Authorized home network security assessment — identified an outdated, internet-facing UPnP daemon (MiniUPnPd 1.8) affected by multiple denial-of-service CVEs. Documented Nmap methodology, validated scanner output against authoritative CVE records, and deployed custom Suricata rules to monitor port 1900 traffic in Security Onion.

## Overview

This repository contains a detailed account of the steps and procedures used to find multiple vulnerabilities and secure a home network. Upon verbal authorization from the network owner, I began reconnaissance on the local subnet. A scan flagged multiple CVEs against an outdated UPnP daemon (MiniUPnPd 1.8) running on a port accessible from the public internet. I validated each flagged CVE against its authoritative record — which caught one false positive the scanner mis-attributed — and confirmed the genuine finding: an internet-exposed, outdated daemon vulnerable to several remote denial-of-service conditions. Security Onion and Suricata with custom rules were deployed in response to monitor network traffic. An analysis of logs concluded no unauthorized or malicious activity.

## Authorization and Rules of Engagement

All testing was done with prior knowledge and verbal consent of the network owner. The scope consisted of the home network subnet and router. Any destructive testing and exploitation of vulnerabilities was off limits.

## Tools Used

* Nmap — Network and vulnerability scanning
* Kali Linux — Pen Testing OS
* Security Onion — Network monitoring OS
* Suricata — Intrusion detection and custom rule implementation
* Zeek — Network Traffic analysis and logging

## Findings Summary

The primary finding is MiniUPnPd 1.8 running on port 1900 while being WAN facing — an outdated daemon exposed to the public internet. The exposure itself is the core misconfiguration: UPnP is designed for internal network use and should never be reachable from outside.

The daemon is affected by multiple confirmed remote denial-of-service vulnerabilities. CVSS scores below were verified against authoritative CVE records (NVD / vendor advisories), not taken from scanner output:

* CVE-2019-12108 — 7.5 HIGH — DoS (NULL pointer dereference, upnpsoap.c)
* CVE-2019-12109 — 7.5 HIGH — DoS (NULL pointer dereference, upnpsoap.c)
* CVE-2019-12111 — 7.5 HIGH — DoS (NULL pointer dereference, pcpserver.c)
* CVE-2026-5720 — 7.1 HIGH — DoS / information disclosure (integer underflow, SOAPAction parsing)

Every confirmed finding is a denial-of-service condition (CVSS availability impact, no confidentiality or integrity impact). No remote code execution vulnerability was confirmed against this daemon.

The following were flagged by the scanner but could not be confirmed against the daemon and are listed separately:

* CVE-2017-1000494 — attributed to a parser file shared between the client and daemon codebases; applies as DoS if present, but daemon applicability is unconfirmed.
* CVE-2013-2600 — CVE database records show a client/daemon naming ambiguity for this ID; version applicability against this daemon is unconfirmed.

## Findings Note

The scanner's highest-severity hit was CVE-2017-8798 (reported as 9.8 Critical). On validation against the authoritative record, this CVE affects the MiniUPnP **client** library (miniupnpc), not the **daemon** (miniupnpd) running on the router — and its public exploit (EDB-ID:43501) is a client-side denial of service, not router code execution. The scanner cross-matched it onto the daemon via overlapping CPE data. It is documented here as a false positive rather than a finding. Validating flagged CVEs against their source records, rather than trusting scanner output, is what separated the genuine findings from the cross-matched one.

CVE-2026-5720 also differs from the others in attack vector — its CVSS 4.0 vector specifies adjacent (AV:A), meaning exploitation requires local network access rather than internet exposure. (NVD additionally lists a CVSS 3.1 score of 9.1 under a network vector; the 4.0 adjacent scoring is cited here as the more representative real-world exposure.) It is included because it affects the same daemon, but does not carry the same external-exposure risk as the WAN-facing DoS conditions.

## Repository Structure

```
home-network-security-assessment/
├── README.md
├── 01-methodology/
│   ├── 01_nmap_recon.md
│   └── 02_security_onion_monitoring.md
├── 02-findings/
│   └── miniupnpd_exposure.md
├── 03-evidence/
│   ├── hunt_query.txt
│   ├── nmap_output_redacted.txt
│   └── suricata_rule.txt
└── 04-remediation/
    └── notes.md
```
