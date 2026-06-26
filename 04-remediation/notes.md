# Remediation — MiniUPnPd 1.8 WAN-Facing Exposure

## Summary
The problem is an outdated UPnP daemon (MiniUPnPd 1.8) that was reachable from the WAN. Remediation breaks into two layers: the ideal preventive fix, and the detective control actually deployed. Preventive controls weren't possible in this environment. The reasoning for that, and the compensating control deployed instead, follow below.

## Preventive Controls — The Ideal Fix
The first and most effective step would be reconfiguring the router so port 1900 is restricted to the LAN (local area network) only. UPnP is designed for internal use and should never be reachable from the public internet.

The second step is patching the daemon itself. Per the CVE-2026-5720 advisory, any version of MiniUPnPd below 2.3.10 is affected, so the daemon would need to be brought up to 2.3.10 or later. On this device that isn't a standalone update: MiniUPnPd is bundled into the router's firmware, so patching depends on TP-Link releasing updated firmware for the Deco S4R that ships a fixed daemon version. Until such a release is installed, the vulnerable daemon stays in place.

As an additional layer, a firewall rule dropping inbound WAN traffic to port 1900 would block external reachability even if the daemon itself stays unpatched. That's defense in depth rather than relying on a single control.

## Why Preventive Wasn't Deployable
Preventive methods weren't available, due to a lack of ownership over the router and lost admin credentials. That blocks the preventive control of taking port 1900 off the WAN. When prevention isn't possible, the next best resolution is detection. The detective control deployed here was Security Onion running a custom Suricata rule (sid:9000001) that alerts on external probes to port 1900. The detection design is documented in 01-methodology/02_security_onion_monitoring.md.

## Why Detection Fits the Threat
A detective control is a reasonable fit given the nature of the findings. The confirmed vulnerabilities are mostly denial-of-service conditions, with one information-disclosure finding (CVE-2013-2600) and one cross-category bug (CVE-2026-5720, an integer underflow that can cause either DoS or information disclosure).

For the DoS-class findings, detection fits well: with denial-of-service, the most useful things to know are whether an attack is happening and when. A rule that alerts on external probes provides exactly that awareness.

Detection fits the information-disclosure finding less cleanly. With a memory-leak bug, the damage (data exposure) has already happened by the time an alert fires, so detection offers awareness but not prevention of the actual harm. This is an honest limitation of a detective-only approach: it suits the availability threats better than the confidentiality one.

## Residual Risk
Detective controls are only a band-aid; they don't solve the underlying exposure. The daemon is still WAN-facing and vulnerable. The monitoring sensor also can't see WAN-side unicast, which severely blunts its efficacy.
