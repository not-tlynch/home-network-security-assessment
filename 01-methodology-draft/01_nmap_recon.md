# Nmap Reconnaissance Methodology

## Objective
The objective of reconnaissance was to find attack vectors by scanning the local subnet. Using Nmap, I discovered hosts, services, and versions, then validated each flagged vulnerability against its authoritative CVE record rather than trusting scanner output. I also verified that the affected service was WAN facing through an external scan.

## Authorization
Verbal authorization was given prior to scanning; scope consisted of the local subnet and router.

## Phase 1 - Host Discovery & Service Detection
`nmap -sV 192.168.68.0/24` — here `nmap` invokes the scanner, `-sV` finds the service/version, and `192.168.68.0/24` is the target subnet in CIDR notation.

The scan identified the router at 192.168.68.1 with four open TCP ports:

* 53/tcp — domain (ISC BIND)
* 80/tcp — http (OpenWrt uHTTPd)
* 443/tcp — ssl/https
* 1900/tcp — upnp (MiniUPnP 1.8 — TP-LINK router, UPnP 1.1)

Port 1900 is the relevant finding: an outdated MiniUPnPd 1.8 daemon, a version dating to 2014. The service version string here is what drives the entire assessment — the version is what the vulnerability scan matches CVEs against in Phase 2.

## Phase 2 - Vulnerability Scan
`nmap -sV --script vuln 192.168.68.0/24 -oN router_scan.txt` — here `nmap` invokes the scanner, `-sV` finds the service/version, `--script vuln` activates the NSE to compare detected services and versions against known vulnerabilities, `192.168.68.0/24` is the target subnet, and `-oN router_scan.txt` saves the output to a text file. (The redacted output can be viewed under `home-network-security-assessment/03-evidence/nmap_output_redacted.txt`.)

The `--script vuln` output is a starting point, not a conclusion. NSE matches CVEs against service version strings via CPE data, which can over-associate vulnerabilities — including across the miniupnpc (client) / miniupnpd (daemon) boundary. Each flagged CVE was therefore validated against its authoritative record before being treated as a finding. See `02-findings/` for the validated results, including one scanner false positive caught this way.


The `vulners` script returned a list of CVEs and public exploits matched against the daemon's CPE string (`cpe:/a:miniupnp_project:miniupnpd:1.8`), the highest being CVE-2017-8798 and EDB-ID:43501 at 9.8. Validation against the authoritative records reordered this picture significantly:

* The 9.8 CVE-2017-8798 hit is a false positive — it affects the MiniUPnP client library (miniupnpc), not the daemon. The scanner matched it via the shared CPE. (Full breakdown in `02-findings/`.)
* The genuine daemon findings are denial-of-service conditions: CVE-2019-12108, CVE-2019-12109, CVE-2019-12111 (all 7.5, verified), and CVE-2026-5720 (7.1, verified).
* CVE-2017-1000494 and CVE-2013-2600 could not be confirmed against this daemon version and are noted as unconfirmed rather than treated as findings.

The HTTP scripts against ports 80 and 443 returned clean — no XSS or CSRF found. The CVE-2014-3704 check on 443 errored out and was inconclusive.



## Phase 3 - External Exposure Verification
`nmap -p 1900 [REDACTED-PUBLIC-IP]` — here `nmap` invokes the scanner, `-p 1900` specifies the port number, and `[REDACTED-PUBLIC-IP]` is the redacted public IP. This scan was run from outside the home network, so the probe routed out through the ISP and back to the WAN interface — confirming port 1900 was reachable from the public internet rather than only from inside the LAN.

The external scan returned port 1900 as open, confirming the UPnP daemon was reachable from the public internet — not merely from inside the LAN. This is the core risk: UPnP is designed for internal network use only and should never be exposed to the WAN. Combined with the outdated daemon version, an internet-facing MiniUPnPd 1.8 is reachable by anyone who scans the address.
