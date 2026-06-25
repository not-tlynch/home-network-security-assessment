# home-network-security-assessment

Authorized home network assessment. Found an internet-facing, outdated UPnP daemon (MiniUPnPd 1.8) with multiple DoS CVEs. Validated scanner output against source records, documented Nmap methodology, deployed custom Suricata monitoring in Security Onion.

## Overview

This repository documents how I found and helped fix multiple vulnerabilities on a home network. With verbal authorization from the network owner, I started reconnaissance on the local subnet. A scan flagged multiple CVEs against an outdated UPnP daemon (MiniUPnPd 1.8) running on a port reachable from the public internet. I validated each CVE against its authoritative record, which caught one false positive the scanner had mis-attributed, and confirmed the real finding: an internet-exposed, outdated daemon vulnerable to several remote denial-of-service conditions. In response I deployed Security Onion and Suricata with custom rules to monitor traffic. Log analysis turned up no unauthorized or malicious activity.

## Authorization and Rules of Engagement

All testing was done with the prior knowledge and verbal consent of the network owner. The scope was the home subnet and router. Destructive testing and exploitation of vulnerabilities were off limits.

## Tools Used

* Nmap: network and vulnerability scanning
* Kali Linux: pen testing OS
* Security Onion: network monitoring OS
* Suricata: intrusion detection and custom rule implementation
* Zeek: network traffic analysis and logging

## Findings Summary

The primary finding is MiniUPnPd 1.8 running on port 1900 while WAN-facing: an outdated daemon exposed to the public internet. That exposure is the core misconfiguration. UPnP is designed for internal network use and should never be reachable from outside.

The daemon is affected by multiple confirmed vulnerabilities: mostly remote denial-of-service, plus one remote information-disclosure and one local-access bug. The CVSS scores below were verified against authoritative CVE records (NVD and vendor advisories), not taken from scanner output:

* CVE-2019-12108: 7.5 HIGH, DoS (NULL pointer dereference, upnpsoap.c)
* CVE-2019-12109: 7.5 HIGH, DoS (NULL pointer dereference, upnpsoap.c)
* CVE-2019-12111: 7.5 HIGH, DoS (NULL pointer dereference, pcpserver.c)
* CVE-2013-2600: 7.5 HIGH, information disclosure (improper snprintf() use; the NVD description names miniupnpd directly)
* CVE-2017-1000494: 7.8 HIGH, local-access DoS / memory corruption (uninitialized stack variable, upnpreplyparse.c; miniupnpd < 2.0). Local vector (AV:L), so it does not contribute to internet-exposure risk.
* CVE-2026-5720: score under NVD reanalysis, DoS / information disclosure (integer underflow in SOAPAction header parsing)

The confirmed findings fall into three impact classes: remote denial-of-service (CVE-2019-12108, -12109, -12111, availability impact), remote information disclosure (CVE-2013-2600, confidentiality impact), and one local-access memory-corruption bug (CVE-2017-1000494, local vector). No remote code execution was confirmed against this daemon. A sixth finding, CVE-2026-5720 (DoS / information disclosure), is remotely triggered per its NVD description but is still undergoing reanalysis, so its formal severity is not finalized at the time of writing.

## Findings Note — False Positive

The scanner's highest-severity hit was CVE-2017-8798 (reported as 9.8 Critical). When I validated it against the authoritative record, it turned out to affect the MiniUPnP **client** library (miniupnpc), not the **daemon** (miniupnpd) running on the router. Its public exploit (EDB-ID:43501) is a client-side denial of service, not router code execution. The scanner had cross-matched it onto the daemon through overlapping CPE data. I've documented it here as a false positive rather than a finding. Validating flagged CVEs against their source records, instead of trusting scanner output, is what separated the genuine findings from the cross-matched one.

CVE-2026-5720 is the one finding whose severity isn't settled yet. Its NVD record is currently undergoing reanalysis. The written description says a remote attacker can trigger it by sending a malformed SOAPAction header, but the formal CVSS vector is still being enriched. Published scores are contested between 7.1 (CVSS 4.0, adjacent) and 9.1 (CVSS 3.1, network), and the gap hinges entirely on whether the attack vector is finalized as adjacent or network. Rather than commit to either while the record is in flux, I've documented it as remote-per-description with formal severity pending. If reanalysis confirms a network vector, the finding moves into the same WAN-facing exposure class as the remote DoS conditions. If it's adjacent, it requires a local-network foothold and doesn't add to the internet-exposure risk.

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
│   ├── rule_9000001_validation.md
│   └── suricata_rule.txt
└── 04-remediation/
    └── notes.md
```
