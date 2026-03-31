# SniffCore Demo Walkthrough

This is the quickest way to show `SniffCore` to someone without talking for ten minutes before they see anything useful.

## The Demo Story

Start with the clean baseline capture and the suspicious capture from `tests/fixtures/`.

The baseline represents what the lab should look like when the expected DHCP server and expected STP sender are the only infrastructure voices on the wire.

The suspicious capture adds three kinds of drift:

- an extra ARP reply source for the gateway IP
- an unexpected DHCP offer source
- a new BPDU sender

That gives you a clean before-and-after comparison instead of a random packet dump.

## The Command

```powershell
python -m sniffcore --pcap .\tests\fixtures\phase2_suspect_lab.pcap --baseline-pcap .\tests\fixtures\phase2_baseline_clean.pcap --output-dir .\reports
```

## What To Point Out

When the HTML report opens, show these first:

- the risk score and severity mix
- the baseline comparison block
- the ARP spoofing finding
- the rogue DHCP server finding
- the STP sender drift finding

That sequence tells the story fast and makes the project feel intentional.

## Clean Project Summary

- Built a Layer 2 packet-analysis workflow for controlled lab captures using Python and Scapy
- Added baseline-aware detection for ARP, DHCP, and STP anomalies
- Generated JSON, Markdown, and HTML reports to cut down manual packet triage time

## How To Explain It

If someone asks why this matters, the clean answer is:

This project is about turning noisy local-network captures into something readable and defensible. The hard part is not grabbing packets. The hard part is deciding what deserves attention and presenting that clearly.
