# home-network-security-assessment

Authorized home network assessment — found an internet-facing, outdated UPnP daemon (MiniUPnPd 1.8) with multiple DoS CVEs. Validated scanner output against source records, documented Nmap methodology, deployed custom Suricata monitoring in Security Onion. 

## Overview

This repository contains a detailed account of the steps and procedures used to find multiple vulnerabilities and secure a home network. Upon verbal authorization from the network owner, I began reconnaissance on the local subnet. A scan flagged multiple CVEs against an outdated UPnP daemon (MiniUPnPd 1.8) running on a port accessible from the public internet. I validated each flagged CVE against its authoritative record — which caught one false positive the scanner mis-attributed — and confirmed the genuine finding: an internet-exposed, outdated daemon vulnerable to several remote denial-of-service conditions. Security Onion and Suricata with custom rules were deployed in response to monitor network traffic. An analysis of logs detected no unauthorized or malicious activity.

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

The daemon is affected by multiple confirmed vulnerabilities — primarily remote denial-of-service, plus one remote information-disclosure and one local-access bug. CVSS scores below were verified against authoritative CVE records (NVD / vendor advisories), not taken from scanner output:

* CVE-2019-12108 — 7.5 HIGH — DoS (NULL pointer dereference, upnpsoap.c)
* CVE-2019-12109 — 7.5 HIGH — DoS (NULL pointer dereference, upnpsoap.c)
* CVE-2019-12111 — 7.5 HIGH — DoS (NULL pointer dereference, pcpserver.c)
* CVE-2013-2600 — 7.5 HIGH — information disclosure (improper snprintf() use; NVD description names miniupnpd directly)
* CVE-2017-1000494 — 7.8 HIGH — local-access DoS / memory corruption (uninitialized stack variable, upnpreplyparse.c; miniupnpd < 2.0). Local vector (AV:L) — does not contribute to internet-exposure risk.
* CVE-2026-5720 — score under NVD reanalysis — DoS / information disclosure (integer underflow in SOAPAction header parsing)

The confirmed findings fall into three impact classes: remote denial-of-service (CVE-2019-12108, -12109, -12111 — availability impact), remote information disclosure (CVE-2013-2600 — confidentiality impact), and one local-access memory-corruption bug (CVE-2017-1000494 — local vector). No remote code execution vulnerability was confirmed against this daemon. A sixth finding, CVE-2026-5720 (DoS / information disclosure), is remotely triggered per its NVD description but is undergoing reanalysis; its formal severity is not finalized at time of writing.

All scanner-flagged CVEs were validated against their authoritative records. The one that did not survive validation — CVE-2017-8798 (scanner-rated 9.8 Critical) — affects the MiniUPnPc client library, not the MiniUPnPd daemon, and is documented as a false positive in the findings detail.

## Findings Note

The scanner's highest-severity hit was CVE-2017-8798 (reported as 9.8 Critical). On validation against the authoritative record, this CVE affects the MiniUPnP **client** library (miniupnpc), not the **daemon** (miniupnpd) running on the router — and its public exploit (EDB-ID:43501) is a client-side denial of service, not router code execution. The scanner cross-matched it onto the daemon via overlapping CPE data. It is documented here as a false positive rather than a finding. Validating flagged CVEs against their source records, rather than trusting scanner output, is what separated the genuine findings from the cross-matched one.

CVE-2026-5720 is the one finding whose severity is not yet settled. Its NVD record is currently undergoing reanalysis: the written description indicates a remote attacker can trigger it by sending a malformed SOAPAction header, but the formal CVSS vector is still being enriched. Published scores are contested between 7.1 (CVSS 4.0, adjacent) and 9.1 (CVSS 3.1, network) — a difference that hinges entirely on whether the attack vector is finalized as adjacent or network. Rather than commit to either while the record is in flux, it is documented here as remote-per-description with formal severity pending. If reanalysis confirms a network vector, this finding moves into the same WAN-facing exposure class as the remote DoS conditions; if adjacent, it requires a local-network foothold and does not add to the internet-exposure risk.

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
│   ├── external_scan_redacted.txt
│   ├── hunt_query.txt
│   ├── nmap_output_redacted.txt
│   └── suricata_rule.txt
└── 04-remediation/
    └── notes.md
```
