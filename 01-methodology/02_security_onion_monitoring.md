# Security Onion Monitoring — Detecting External Probes Against a WAN-Exposed UPnP Service


## 1. Objective

Security Onion was installed to monitor for any external probing around port 1900, which would indicate reconnaissance. The MiniUPnPd service on port 1900 suffers from several denial-of-service CVEs. The goal is to find out whether any external sources are actually probing this service.
This file `(02_security_onion_monitoring.md)` focuses on the defensive side; for the offensive recon, see `(01_nmap_recon.md)`



## 2. Why Detection — Compensating Control Rationale

The most effective solution would be to reconfigure the router so port 1900 is no longer WAN-facing. The constraint here is a lack of ownership over the router and lost admin credentials.
When prevention isn't possible, the next best resolution is detection. Implementing a detective control provides awareness where prevention falls short. This approach fits the threat landscape of DoS attacks well: with denial-of-service, the most useful things to know are whether it's happening and when.


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


### 3.2 Traffic Visibility — the honest constraint

A VMware vSwitch behaves like a learning switch, not a hub. That means unicast between two machines is handed only to the destination port — whereas broadcast and multicast flood to every port, which is why the sensor saw the Roku SSDP beacons (SSDP is multicast) but not unicast probes. Promiscuous mode is necessary but not sufficient: in promiscuous mode the NIC can accept frames not addressed to it, but the vSwitch still has to deliver them to the port in the first place.

A consumer Deco router cannot SPAN or mirror WAN-side traffic to the sensor. So even with Security Onion fully working, "no external probes observed" is bounded by what could physically reach the sensor's vantage point — meaning absence of alerts is not proof that external probing isn't happening. Adding a managed switch with a SPAN port is the next logical step, allowing full utilization of Security Onion.


## Detection Strategy
Signature or rule-based detection was the centerpiece of the strategy. I have a known service, on a known port, with a known CVE — the problem on the network is well-defined, so I based the rule directly on it. The rule is simple: it alerts on any external probing toward port 1900. Behavioral detection through Zeek would be both more challenging and less suited to this problem. One tight rule filtering for external traffic isn't prone to the same false positives that broad behavioral analysis is. Inferring about a pattern is probabilistic, while using a set of rules is deterministic: `Port 1900 + external IP + UDP`

## 5. The Custom Rule — `sid:9000001`

The rule as deployed (The `msg` field names CVE-2017-8798, which was determined to be a false positive for affecting the routers daemon, instead affecting the MiniUPnPc client library)

```
alert udp !192.168.68.0/24 any -> 192.168.68.1 1900 (msg:"CVE-2017-8798 External UPnP probe to router"; sid:9000001; rev:2;)
```

| Rule clause | Purpose |
|---|---|
| `alert udp` | Alert on UDP traffic |
| `!192.168.68.0/24` | Source must NOT be local — external probes only; suppresses internal Roku SSDP chatter |
| `any` | Any source port |
| `-> 192.168.68.1 1900` | Destined for the router on port 1900 (UPnP/SSDP) |
| `sid:9000001` | Unique signature ID (local rules conventionally use 9000000+) |
| `rev:2` | Revision 2 of the rule |
| `msg:"..."` | Alert text written to the event log |

**Note on the `msg` field:** The message names CVE-2017-8798, which this assessment determined to be a false positive — it affects the MiniUPnPc client library, not the MiniUPnPd daemon on the router. The rule's real purpose is detecting external probes to the WAN-exposed UPnP service, which remains valid regardless. A future `rev:3` will retitle the message to decouple it from the disputed CVE.

## 6. Establishing Baseline — What Normal Looks Like

To characterize normal traffic, I started by observing what was already happening on the network. Every two minutes or so, the Roku TVs broadcast multicast SSDP packets announcing their presence — predictable, routine chatter. I did spot one timing anomaly in the logs, but on analysis it was benign. Establishing this baseline matters: knowing what normal looks like is what lets a rule target the genuinely abnormal without drowning in routine traffic.


### 6.1 SSDP beacon baseline

Roku TVs beacon on port 1900 (SSDP multicast) every two minutes or so, as noted earlier. This matters because it directly informed the (`!192.168.68.0/24`) clause of the rule, where I exclude internal traffic — this is exactly the routine chatter that clause is there to filter out. I can regularly expect this kind of traffic from this service without raising alarm. A Roku normally beacons for three things: local device discovery, keeping the connection alive, and telemetry/ad polling. These all originate from within the network; the rule only fires on external IPs, i.e. anyone potentially scanning.

**The command used:** `sudo tcpdump -i bond0 -n port 1900`
 
- `sudo` — escalate privileges; raw packet capture requires root
- `tcpdump` — the capture tool
- `-i bond0` — listen on the monitor interface (bond0, physical member ens34)
- `-n` — don't resolve names to IPs, keeps output fast and readable
- `port 1900` — filter to just SSDP traffic for port 1900


 ## 6.2 Observed Timing Anomaly
I observed a timing anomaly in the Roku beaconing pattern. I wasn't able to determine a cause for it, but there was no exploitable vector associated with it, making it relatively benign.



## 7. Rule Validation

As mentioned, issues with VMware's vSwitch meant I couldn't see unicast traffic. To validate the rule, I opted for an offline testing environment: I took the rule's logic and tested it against a crafted packet read directly from a pcap file, rather than sniffing a live interface. Because the rule excludes traffic from 192.168.68.0/24, I used Scapy to craft a packet with a spoofed external source — the only way to exercise that exclusion clause, since any packet sent from inside the network is internal by definition. The rule fired as expected against the spoofed packet; the full eve.json output is in [`rule_9000001_validation.md`](../03-evidence/rule_9000001_validation.md).
This proves the rule's match logic works. While not live evidence, it remains a cornerstone of this repository.


The rule's match logic was validated offline; full reproduction trail and `eve.json` output are in [`rule_9000001_validation.md`](../03-evidence/rule_9000001_validation.md).


## 8. Monitoring Period Findings
My deployment of Security Onion was not continuous — it hit a wall during the SSD crunch and had to be recovered, and the original log files from before the outage are lost. What I can say is that during its operational window, Security Onion saw and handled traffic correctly, and produced no alerts on 9000001.

Note: the absence of 9000001 alerts is not evidence that no probing occurred. The sensor could not see WAN-side unicast — the traffic the rule is written to catch — so it had no way to observe an external probe in the first place. Absence of alerts here reflects the sensor's vantage point, not the absence of an attacker.

## 9. Limitations

- **Offline validation, not live — The rule's logic is proven, but the rule was never observed firing on live traffic.**
- **Sensor vantage point couldn't see WAN-side unicast — A consumer Deco router can't SPAN or mirror traffic to a monitor port, leaving the IDS blind to external unicast packets.**
- **Monitoring was not continuous — An SSD storage overflow caused an outage, and logs from before the outage were lost.**
- **Single-rule, single-port scope — The rule watched port 1900 specifically; no comprehensive network coverage was implemented.**
- **Signature-based detection only — No behavioral or Zeek analysis was implemented, meaning low-and-slow or novel methods could slip past detection**




## 10. Future Work

Most future work for this repo will consist of addressing the limitations listed above. Planned next steps include:

- **SPAN port / managed switch** — directly addresses the unicast blind spot by mirroring traffic to the monitor port.
- **Inline Raspberry Pi gateway** — part of a much larger project; solves the problem of WAN traffic never reaching the LAN by placing the sensor in the path.
- **Behavioral analysis (Zeek)** — addresses the limitation of signature-only detection and adds defense in depth.
- **DHCP reservations and continuous monitoring** — prevents management IP drift on the next deployment and preserves log integrity.


## References / Evidence

**Evidence (this repository):**

- [`rule_9000001_validation.md`](../03-evidence/rule_9000001_validation.md) — offline rule-logic validation; full `eve.json` output and field-by-field clause breakdown
- [`suricata_rule.txt`](../03-evidence/suricata_rule.txt) — the deployed rule (`sid:9000001`, rev:2)
- [`hunt_query.txt`](../03-evidence/hunt_query.txt) — Security Onion Hunt query used during the monitoring period
- Related: [`miniupnpd_exposure.md`](../02-findings/miniupnpd_exposure.md) — the WAN-exposure finding this monitoring supports
- Related: [`notes.md`](../04-remediation/notes.md) — remediation reasoning and compensating-control rationale

**External references:**

- [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) — IPv4 address blocks reserved for documentation; source of the non-routable TEST-NET-3 address (`203.0.113.0/24`) used in offline validation
- [Security Onion documentation](https://docs.securityonion.net/) — Suricata rule management and deployment (version 2.3)
- CVE records — see [`miniupnpd_exposure.md`](../02-findings/miniupnpd_exposure.md) for the full list of confirmed CVEs with authoritative references
