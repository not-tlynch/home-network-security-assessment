# Nmap Reconnaissance Methodology

## Objective
The objective of reconnaissance was to find attack vectors by scanning the local subnet. Using Nmap, I discovered hosts, services, and versions. I also verified that these vulnerabilities are WAN facing through an external scan.

## Authorization
Verbal authorization was given prior to scanning; scope consisted of the local subnet and router.

## Phase 1 - Host Discovery & Service Detection
`nmap -sV 192.168.68.0/24` — here `nmap` invokes the scanner, `-sV` finds the service/version, and `192.168.68.0/24` is the target subnet in CIDR notation.
(what I found)

## Phase 2 - Vulnerability Scan
`nmap -sV --script vuln 192.168.68.0/24 -oN router_scan.txt` — here `nmap` invokes the scanner, `-sV` finds the service/version, `--script vuln` activates the NSE to compare detected services and versions against known vulnerabilities, `192.168.68.0/24` is the target subnet, and `-oN router_scan.txt` saves the output to a text file. (The redacted output can be viewed under `home-network-security-assessment/03-evidence/nmap_output_redacted.txt`.)
(what I found)

## Phase 3 - External Exposure Verification
`nmap -p 1900 [REDACTED-PUBLIC-IP]` — here `nmap` invokes the scanner, `-p 1900` specifies the port number, and `[REDACTED-PUBLIC-IP]` is the redacted public IP.
(what I found)

## Summary
(summary)
