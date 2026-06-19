# Security Onion Monitoring — Detecting External Probes Against a WAN-Exposed UPnP Service

<!--
SKELETON v1 — fill the [FILL IN] markers, then delete every HTML comment before publishing.
Voice: first person SINGULAR ("I"). Solo assessment.
Naming reminder: this file = 01-methodology/02_security_onion_monitoring.md
Story this file must tell: preventive patching wasn't immediately deployable here, so I
deployed a DETECTIVE control (Security Onion + a custom Suricata rule on port 1900),
baselined normal traffic, validated the rule logic, and watched for external exploitation.
Keep the story consistent with README / findings / remediation: 6 confirmed CVEs,
3 impact classes, 1 documented false positive (CVE-2017-8798), WAN exposure = core misconfig.
-->

## 1. Objective

Security Onion was installed to monitor for any external probing around port 1900, which would indicate reconnaissance. The MiniUPnPd service on port 1900 suffers from several denial-of-service CVEs. The goal is to find out whether any external sources are actually probing this service.
This file `(02_security_onion_monitoring.md)` focuses on the defensive side; for the offensive recon, see 01_nmap_recon.md.


[FILL IN: objective paragraph]

---

## 2. Why Detection — Compensating Control Rationale

The most effective solution would be to reconfigure the router so port 1900 is no longer WAN-facing. The constraint here is a lack of ownership over the router and lost admin credentials.
When prevention isn't possible, the next best resolution is detection. Implementing a detective control provides awareness where prevention falls short. This approach fits the threat landscape of DoS attacks well: with denial-of-service, the most useful things to know are whether it's happening and when.


[FILL IN: compensating-control reasoning — keep it aligned with 04-remediation/notes.md]

---

## 3. Monitoring Architecture
 Timeline
 
Original Deployment — Security Onion was fully operational and capable of observing traffic. In fact, SO observed real baseline traffic through Roku SSDP beaconing. It also caught a timing anomaly within that beaconing which, upon analysis, turned out to be benign.



SSD Crunch — Security Onion underwent operational degradation when my SSD crossed the critical disk watermark. This caused Elasticsearch and its associated containers to fail, which knocked out the custom detection rules and caused the management IP to drift, temporarily halting everything.



Recovery — Security Onion was rebuilt and configured back to baseline. With the custom detection rules loaded again, I moved to test them. Here I hit a constraint: live traffic visibility through VMware's vSwitch. A vSwitch forwards unicast frames only to the destination MAC's port, so they are never copied to the monitor port. To test the rule accurately, I opted to run Suricata in offline mode against a crafted rule-violating packet. A SPAN port will be added in the future to improve the monitor port's visibility.


### 3.1 Deployment

The deployment relies on single-node monitoring. Rather than standing up complex enterprise SPAN or TAP infrastructure, the sensor runs as a localized instance tailored to the target segment.

System specification:


Platform — Security Onion, version 2.3.300
Hypervisor — VMware Workstation Pro, hosted on Windows 11
Management interface — ens33, configured as a bridged interface directly on the LAN
Active management IP — 192.168.68.110
Operational note — Due to network IP drift, the boot banner may display an old address (192.168.83.130); this ghost address has been deprecated in favor of the current .68.110.


Division of labor in SO:


Suricata — rule-based detection (where sid:9000001 resides)
Zeek — connection and behavioral logging
eve.json — Suricata's JSON event output
Analyst interaction — Security Onion's web portal


A key takeaway was managing local resource bottlenecks. The VM reached its storage threshold, crossing the ~85% Elasticsearch disk watermark and halting Elasticsearch, which cascaded into container failures. Recovering from that — reconfiguring the box and redeploying the custom rules back to baseline — was its own exercise.

[FILL IN: deployment description — working SO 2.3.300, interfaces/roles, where events land, one honest line on the disk-crunch + recovery]

### 3.2 Traffic Visibility — the honest constraint

A VMware vSwitch behaves like a learning switch, not a hub. That means unicast between two machines is handed only to the destination port — whereas broadcast and multicast flood to every port, which is why the sensor saw the Roku SSDP beacons (SSDP is multicast) but not unicast probes. Promiscuous mode is necessary but not sufficient: in promiscuous mode the NIC can accept frames not addressed to it, but the vSwitch still has to deliver them to the port in the first place.

A consumer Deco router cannot SPAN or mirror WAN-side traffic to the sensor. So even with Security Onion fully working, "no external probes observed" is bounded by what could physically reach the sensor's vantage point — meaning absence of alerts is not proof that external probing isn't happening. Adding a managed switch with a SPAN port is the next logical step, allowing full utilization of Security Onion.

[FILL IN: visibility constraint — vSwitch unicast-vs-multicast mechanism (explains Roku-seen / probe-missed), promiscuous-necessary-not-sufficient, the WAN-unicast caveat = absence-of-alerts isn't absence-of-probing, why this led to offline validation in §7]


## Detection Strategy
---
Signature or rule-based detection was the centerpiece of the strategy. I have a known service, on a known port, with a known CVE — the problem on the network is well-defined, so I based the rule directly on it. The rule is simple: it alerts on any external probing toward port 1900. Behavioral detection through Zeek would be both more challenging and less suited to this problem. One tight rule filtering for external traffic isn't prone to the same false positives that broad behavioral analysis is. Inferring about a pattern is probalistic, while using a set of rules is deterministic: `Port 1900 + external IP + UDP`

[FILL IN: 2-3 sentences on detection approach and why it fits]

---

## 5. The Custom Rule — `sid:9000001`




