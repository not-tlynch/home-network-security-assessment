# Findings — MiniUPnPd 1.8 WAN-Facing Exposure

## Summary


The router uses the outdated MiniUPnPd 1.8 on port 1900. A scan of the public IP address confirmed this service is reachable via the public internet. UPnP (Universal Plug and Play) is a protocol for automatic device discovery and configuration on a network, including port forwarding; MiniUPnPd (the UPnP daemon) is the service that implements it. The 1.8 daemon is affected by multiple confirmed vulnerabilities — primarily remote denial-of-service, plus one information-disclosure and one local-access bug — all verified against authoritative CVE records.


## Affected Service
- **Service:** MiniUPnPd 1.8 (UPnP daemon)
- **Port:** 1900/tcp
- **Device:** TP-Link Deco S4R
- **Exposure:** Internet-facing (confirmed via external scan — see 01-methodology)

## Validated Findings (Confirmed Against Authoritative Records)
- **CVE-2017-1000494** — 7.8 High — CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H — uninitialized stack variable in NameValueParserEndElt (upnpreplyparse.c), miniupnpd < 2.0. Differs from the findings above: this is a **local** attack vector (AV:L) requiring some privilege (PR:L) — not remotely exploitable, so it does not contribute to the internet-exposure risk.
- **CVE-2019-12108** — 7.5 High — CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H 
  — DoS, NULL pointer dereference in GetOutboundPinholeTimeout (upnpsoap.c)
- **CVE-2013-2600** — 7.5 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — information disclosure via improper snprintf() use in miniupnpd. Differs from the DoS findings: this is a **confidentiality-impact** bug (C:H), not denial-of-service — a remote attacker can leak memory contents rather than crash the service.
- **CVE-2019-12109** — 7.5 High — CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — DoS, NULL deref (upnpsoap.c)
- **CVE-2019-12111** — 7.5 High — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — DoS, NULL deref (pcpserver.c)
- **CVE-2026-5720** — severity under NVD reanalysis — DoS / information disclosure via integer underflow in SOAPAction header parsing. The record's description states a remote attacker can trigger an out-of-bounds memory read by sending a malformed SOAPAction header with a single quote: improper length validation in ParseHttpHeaders() underflows to a large unsigned value passed to memchr(), scanning memory past the allocated HTTP request buffer. NVD lists the record as undergoing reanalysis; the formal CVSS vector is not finalized and published scores are contested between 7.1 (CVSS 4.0, adjacent) and 9.1 (CVSS 3.1, network). Documented here as remote-per-description with formal severity pending rather than committing to a contested value.

The confirmed findings fall into three classes: remote denial-of-service (CVE-2019-12108, -12109, -12111 — availability impact, A:H), one remote information-disclosure bug (CVE-2013-2600 — confidentiality impact, C:H), and one local-access memory-corruption bug (CVE-2017-1000494 — local vector, AV:L). None enable remote code execution. A sixth finding, CVE-2026-5720, is remotely triggered per its NVD description (DoS / information disclosure) but is undergoing reanalysis, with formal severity pending at time of writing.

These findings do **not** establish RCE (Remote Code Execution), persistence, or a confirmed network pivot. The confirmed impacts are: crashing the service (availability), one remote memory-disclosure bug that can leak data (confidentiality, CVE-2013-2600), and one local-access bug (CVE-2017-1000494). No single finding grants an attacker code execution or control of the device.

## False Positive — CVE-2017-8798
The false positive arose from the scanner matching CVEs to a version string through CPE data rather than actually testing for the vulnerability. MiniUPnP ships in two forms: a client library (miniupnpc) used by applications such as a PC's software, and a daemon (miniupnpd) that runs in the background on a host such as a router. The scanner matched on version data that didn't cleanly separate client from daemon, so a client-side CVE was attributed to the router's daemon — where it carried a far more serious 9.8 rating than it warranted. That single character, c versus d, is the difference between two distinct programs, and it collapsed in the automated matching.

- Scanner flagged CVE-2017-8798 at 9.8 Critical against the daemon CPE
- Authoritative record: this CVE affects the miniupnp **client** library (miniupnpc), not the **daemon** (miniupnpd)
- Its public exploit (EDB-ID:43501) is titled a client-side remote DoS, not router RCE
- The match was made against the daemon CPE string `cpe:/a:miniupnp_project:miniupnpd:1.8` — the specific string that carried the client CVE onto the daemon

By treating the scan result as fallible, I identified this as a false positive. Without that validation step, a false 9.8 Critical would have been reported as the primary finding.

## Impact
The confirmed findings are remotely exploitable against an internet-facing daemon: an attacker on the public internet can crash the service (the DoS findings) or leak memory contents (CVE-2013-2600), without needing any prior access. One additional finding (CVE-2017-1000494) requires local access and is lower-risk in this context.


The core issue lies outside the CVEs entirely: UPnP is exposed to the WAN due to the router's misconfiguration. This contradicts the protocol's intended purpose, as UPnP is designed for internal network use only.

## Remediation

There is an umbrella of controls to deploy. The most notable are preventive: reconfiguring the router to limit port 1900 to LAN activity only, and a firewall that blocks external/WAN access and drops probing packets before they reach the service. Where preventive controls aren't available, detective controls fill the gap — a custom Suricata rule and Zeek logging were deployed via Security Onion to alert on external probes to port 1900.

## References
**Confirmed daemon CVEs (verified against authoritative records):**
- CVE-2013-2600 — https://nvd.nist.gov/vuln/detail/CVE-2013-2600
- CVE-2017-1000494 — https://nvd.nist.gov/vuln/detail/CVE-2017-1000494
- CVE-2019-12108 — https://nvd.nist.gov/vuln/detail/CVE-2019-12108 — https://osv.dev/vulnerability/CVE-2019-12108
- CVE-2019-12109 — https://nvd.nist.gov/vuln/detail/CVE-2019-12109 — https://osv.dev/vulnerability/CVE-2019-12109
- CVE-2019-12111 — https://nvd.nist.gov/vuln/detail/CVE-2019-12111 — https://osv.dev/vulnerability/CVE-2019-12111
- CVE-2026-5720 — https://nvd.nist.gov/vuln/detail/CVE-2026-5720 — https://vulnerability.circl.lu/vuln/cve-2026-5720

**False positive — CVE-2017-8798 (affects miniupnpc client, not miniupnpd daemon):**
- CVE record — https://nvd.nist.gov/vuln/detail/CVE-2017-8798
- Public exploit (client-side DoS) — https://www.exploit-db.com/exploits/43501
- Full disclosure detail — https://seclists.org/fulldisclosure/2017/May/43
