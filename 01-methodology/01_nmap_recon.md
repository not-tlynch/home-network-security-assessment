# Nmap Reconnaissance Methodology

## Objective
Reconnaissance aimed to find attack vectors by scanning the local subnet. Using Nmap, I discovered hosts, services, and versions, then validated each flagged vulnerability against its authoritative CVE record rather than trusting scanner output. I also verified that the affected service was WAN facing through an external scan.

## Authorization
I had verbal authorization before scanning. The scope was the local subnet and router.

## Phase 1 - Host Discovery & Service Detection
`nmap -sV 192.168.68.0/24`: here `nmap` invokes the scanner, `-sV` finds the service/version, and `192.168.68.0/24` is the target subnet in CIDR notation.

The scan identified the router at 192.168.68.1 with four open TCP ports:

* 53/tcp: domain (ISC BIND)
* 80/tcp: http (OpenWrt uHTTPd)
* 443/tcp: ssl/https
* 1900/tcp: upnp (MiniUPnP 1.8, TP-LINK router, UPnP 1.1)
* **Note:** TCP on port 1900 is normal. Every confirmed CVE lives in the SOAP (control) path, which is reached over TCP.

Port 1900 is the relevant finding: an outdated MiniUPnPd 1.8 daemon, a version dating to 2014. Nmap labels the service "MiniUPnP"; this is the daemon, miniupnpd. The service version string is the pivot the whole assessment turns on. It's what the Phase 2 vulnerability scan matches CVEs against.

## Phase 2 - Vulnerability Scan
`nmap -sV --script vuln 192.168.68.1 -oN router_scan.txt`: here `nmap` invokes the scanner, `-sV` finds the service/version, `--script vuln` activates the NSE to compare detected services and versions against known vulnerabilities, `192.168.68.1` is the router (the focus of the vulnerability scan after subnet discovery in Phase 1), and `-oN router_scan.txt` saves the output to a text file. (The redacted output can be viewed under `home-network-security-assessment/03-evidence/nmap_output_redacted.txt`.)

The `--script vuln` output is a starting point, not a conclusion. NSE matches CVEs against service version strings via CPE data, which can over-associate vulnerabilities, including across the miniupnpc (client) / miniupnpd (daemon) boundary. Each flagged CVE was therefore validated against its authoritative record before being treated as a finding. See `02-findings/` for the validated results, including one scanner false positive caught this way.

The `vulners` script returned a list of CVEs and public exploits matched against the daemon's CPE string (`cpe:/a:miniupnp_project:miniupnpd:1.8`), the highest being CVE-2017-8798 and EDB-ID:43501 at 9.8. Validation against the authoritative records reordered this picture significantly:

* The 9.8 CVE-2017-8798 hit is a false positive: it affects the MiniUPnPc client library, not the MiniUPnPd daemon. The scanner matched it via the shared CPE. (Full breakdown in `02-findings/`.)
* The confirmed daemon findings, all validated against their NVD records: CVE-2019-12108, CVE-2019-12109, CVE-2019-12111 (DoS, 7.5), CVE-2013-2600 (information disclosure, 7.5), and CVE-2017-1000494 (local-access, 7.8).
* CVE-2026-5720 (DoS / information disclosure) is confirmed against the daemon, but its NVD record is undergoing reanalysis; severity score pending, not finalized at time of writing.

The HTTP scripts against ports 80 and 443 returned clean, with no XSS or CSRF found. The CVE-2014-3704 check on 443 errored out and was inconclusive.

## Phase 3 - External Exposure Verification
`nmap -sV --script vuln [REDACTED-PUBLIC-IP]`: here `nmap` invokes the scanner, `-sV` finds the service/version, `--script vuln` runs the NSE vulnerability scripts, and `[REDACTED-PUBLIC-IP]` is the redacted public IP. I ran this scan from outside the home network, so the probes routed out through the ISP and back to the WAN interface, confirming exposure from the public internet rather than only from inside the LAN.

The external scan returned three open ports on the public IP: 80 (OpenWrt admin httpd), 443 (https), and 1900 (MiniUPnPd 1.8). Port 1900 being reachable from outside confirms the UPnP daemon is internet-facing, which is the core exposure finding. UPnP is meant for internal network use only and should never be exposed to the WAN, so an internet-facing MiniUPnPd 1.8 is reachable by anyone who scans the address. Port 80 (the router's web admin interface) responded but refused the probe because the request came from a public source address. The admin panel only trusts internal (RFC1918) sources, so anything arriving from the WAN gets rejected. That is a partial access restriction, not a fully open admin panel, and the contrast is worth noting: the admin interface is locked to the LAN while 1900 stays reachable from anywhere. Full output in `03-evidence/external_scan_redacted.txt`.
