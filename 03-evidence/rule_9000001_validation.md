# Custom Rule `9000001` — Detection Logic Validation

**Note on the msg field:** This validates rule `9000001` as originally authored (rev:2). The msg names CVE-2017-8798, which this assessment separately determined to be a false positive for the daemon (it affects the MiniUPnPc client library — see 02-findings/). The rule's detection purpose — alerting on external probes to the WAN-facing UPnP service — does not depend on that label. A planned rev:3 retitles the msg to remove the reference.

**Test type:** Offline rule-logic validation (Suricata read-mode against a crafted probe packet)
**Date:** June 19, 2026
**Engine:** Suricata 8.0.5 RELEASE (standalone, Kali)
**Rule under test:** `sid:9000001` rev:2 — CVE-2017-8798 external UPnP probe detection
**Result:** PASS — alert fired, all rule fields matched.

---

## OFFICIAL OUTPUT

The following is the unmodified, official output captured directly from the validation run.

### Engine run — packet ingested

```
$ suricata -r probe_9000001.pcap -S suricata_rule.rules -l ./so_test/
i: suricata: This is Suricata version 8.0.5 RELEASE running in USER mode
i: threads: Threads created -> RX: 1 W: 4 FM: 1 FR: 1   Engine started.
i: suricata: Signal Received.  Stopping engine.
i: pcap: read 1 file, 1 packets, 49 bytes
```

### Alert produced — official `eve.json` event

```
$ grep 9000001 ./so_test/eve.json
```

```json
{
  "timestamp": "2026-06-19T08:38:31.981559-0400",
  "flow_id": 2245439028924453,
  "pcap_cnt": 1,
  "event_type": "alert",
  "src_ip": "203.0.113.50",
  "src_port": 49152,
  "dest_ip": "192.168.68.1",
  "dest_port": 1900,
  "proto": "UDP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 9000001,
    "rev": 2,
    "signature": "CVE-2017-8798 External UPnP probe to router",
    "category": "",
    "severity": 3
  },
  "app_proto": "failed",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 1,
    "pkts_toclient": 0,
    "bytes_toserver": 49,
    "bytes_toclient": 0,
    "start": "2026-06-19T08:38:31.981559-0400",
    "src_ip": "203.0.113.50",
    "dest_ip": "192.168.68.1",
    "src_port": 49152,
    "dest_port": 1900
  }
}
```

---

## What this proves — alert fields mapped to rule fields

The rule under test:

```
alert udp !192.168.68.0/24 any -> 192.168.68.1 1900 (msg:"CVE-2017-8798 External UPnP probe to router"; sid:9000001; rev:2;)
```

| Rule clause | Output field | Match |
|---|---|---|
| `alert udp` | `"event_type":"alert"`, `"proto":"UDP"` | ✔ |
| `!192.168.68.0/24` (external source only) | `"src_ip":"203.0.113.50"` (external) — alert fired, so the negation matched | ✔ |
| `-> 192.168.68.1` | `"dest_ip":"192.168.68.1"` | ✔ |
| `1900` | `"dest_port":1900` | ✔ |
| `sid:9000001` | `"signature_id":9000001` | ✔ |
| `rev:2` | `"rev":2` | ✔ |
| `msg:"..."` | `"signature":"CVE-2017-8798 External UPnP probe to router"` | ✔ |

The external-source-only logic (`!192.168.68.0/24`) is the field that could not be exercised from a host on the live `192.168.68.0/24` LAN — internal test traffic is suppressed by design. The crafted probe uses a spoofed external source (`203.0.113.50`, RFC 5737 TEST-NET-3, non-routable), which is what allowed this clause to be validated directly.

### Notes on two non-error fields
- `"action":"allowed"` — correct for IDS mode. The engine logs the alert and passes the packet; "allowed" indicates it was not running in inline-drop mode. This is not a missed detection.
- `"app_proto":"failed"` — the crafted payload was not a full SSDP transaction. Irrelevant to this rule, which matches on protocol, destination, and port rather than application-layer parsing. The alert fired regardless.

---

## How this output was produced (reproduction trail)

This was an **offline** validation: Suricata reads the packet from a `.pcap` file rather than from a live interface. This deliberately removes the virtual-switch traffic-visibility constraint that blocks inter-host monitoring in the VMware lab, isolating the test to the rule logic itself.

**1. Craft the probe packet (Scapy, Kali):**
```python
from scapy.all import IP, UDP, Raw, wrpcap
pkt = IP(src="203.0.113.50", dst="192.168.68.1")/UDP(sport=49152, dport=1900)/Raw(load=b"M-SEARCH * HTTP/1.1\r\n")
wrpcap("probe_9000001.pcap", pkt)
```
- External spoofed source satisfies `!192.168.68.0/24`; destination + `dport=1900` satisfy the rest of the rule. `wrpcap` writes the packet to disk; nothing is transmitted.

**2. Isolate the rule under test:**
```bash
echo 'alert udp !192.168.68.0/24 any -> 192.168.68.1 1900 (msg:"CVE-2017-8798 External UPnP probe to router"; sid:9000001; rev:2;)' > suricata_rule.rules
```

**3. Run Suricata in offline read-mode:**
```bash
suricata -r probe_9000001.pcap -S suricata_rule.rules -l ./so_test/
```
- `-r <file>` — read packets from the pcap instead of sniffing an interface.
- `-S <file>` — load **only** this rule file (capital S), ignoring the default ruleset, for a clean isolated test.
- `-l <dir>` — log directory where `eve.json` is written.

**4. Confirm the hit:**
```bash
grep 9000001 ./so_test/eve.json
```

---

## Scope and honesty statement

This artifact demonstrates that the **detection logic** of rule `9000001` is correct: given a packet matching its criteria, the rule fires and produces the expected alert. This is offline signature validation, **not** an observation of the rule firing on live production network traffic. On the Security Onion deployment the same rule (byte-for-byte identical) is authored, compiled into the live ruleset (`all.rules`), and loaded by Suricata; this test independently confirms its match logic.
