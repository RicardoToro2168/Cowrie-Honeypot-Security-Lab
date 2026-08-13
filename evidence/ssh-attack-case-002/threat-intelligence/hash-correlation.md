# Malware Hash Correlation

## Purpose

This file documents public threat-intelligence matches for malware artifacts captured during **SSH Attack Case 002**.

The hashes below were recorded by Cowrie when the attacker uploaded the files. Public-source matches are used to corroborate that the captured binaries are known malicious/mining-related artifacts.

Hash matches are **not** used alone to attribute the samples to a malware family or threat actor.

---

## Cowrie-Recorded Binary Hashes

| Cowrie Filename | SHA-256 |
|---|---|
| `redtail.arm7` | `d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141` |
| `redtail.arm8` | `d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e` |
| `redtail.i686` | `8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70` |
| `redtail.riscv` | `3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39` |
| `redtail.x86_64` | `f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987` |

The corresponding transfer events are retained separately in:

`evidence/ssh-attack-case-002/cowrie/sftp-uploads.json`

---

## TZ-CERT Correlation

**Source:** Tanzania Computer Emergency Response Team (TZ-CERT)  
**Report:** Honeypot Weekly Report — Report No. TZ-CERT/WRHP/2026/31  
**Reporting Period:** July 27–August 2, 2026  

TZ-CERT Table 2 lists the top malware samples observed by its honeypot infrastructure for the reporting period. All five binary SHA-256 values captured in SSH Attack Case 002 appear in that table.

| Cowrie Filename | SHA-256 | TZ-CERT Detection Label |
|---|---|---|
| `redtail.arm7` | `d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141` | `miner.r002c0xh226/abminer` |
| `redtail.arm8` | `d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e` | `miner.malxmr/usblgv26` |
| `redtail.i686` | `8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70` | `trojan.malxmr/usblgv26` |
| `redtail.riscv` | `3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39` | `trojan.abminer/gen3` |
| `redtail.x86_64` | `f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987` | `trojan.malxmr/usblgv26` |

### Finding

All five architecture-specific payloads captured by Cowrie have an **exact SHA-256 match** in independent honeypot telemetry published by TZ-CERT.

The public report categorizes the samples using mining/trojan-related detection labels. This provides strong independent evidence that the binaries transferred during the Cowrie session are malicious and associated with cryptocurrency-mining activity.

---

## Classification Caveat

Malware-family and detection names can vary substantially among antivirus vendors, sandboxes, and threat-intelligence providers.

For that reason:

- The TZ-CERT detection labels are recorded exactly as published.
- The labels are treated as evidence of malicious/mining-related classification.
- The labels are **not** treated as definitive proof of the RedTail family name.
- RedTail attribution for this case is based primarily on the broader behavioral correlation documented in `redtail-correlation.md`.

The exact SHA-256 match is stronger evidence for sample identity than a vendor-provided malware-family label.

---

## Script Hashes

Cowrie also recorded the following original script hashes:

| Filename | SHA-256 |
|---|---|
| `clean.sh` | `3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892` |
| `setup.sh` | `1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d` |

These hashes are retained as primary IOCs even though the behavioral content of the captured scripts is more useful to the Part 1 assessment than a public malware-family label.

Analyst-reviewed copies of the scripts were modified to permit safe storage and therefore do not have these original hashes. The Cowrie-recorded hashes above remain the authoritative values for the attacker-uploaded artifacts.

---

## Important Correlation Limitation

The attacking IP addresses shown in the TZ-CERT report are part of **TZ-CERT's own honeypot observations**.

They are **not** asserted to be the source IP observed in SSH Attack Case 002, and they should not be added to this case's IOC list merely because they delivered the same samples elsewhere.

The defensible correlation is:

**same SHA-256 → same binary content**

It does not establish:

**same SHA-256 → same human operator or source infrastructure**

---

## Assessment

**Binary maliciousness:** High Confidence  
**Cryptocurrency-mining association:** High Confidence  
**RedTail family attribution from hashes alone:** Insufficient  
**RedTail-related attribution when combined with behavioral evidence:** High Confidence

The hash evidence independently corroborates the malware assessment while the behavioral evidence provides the stronger basis for RedTail attribution.

---

## Source

Tanzania Computer Emergency Response Team (TZ-CERT)  
Honeypot Weekly Report — Report No. TZ-CERT/WRHP/2026/31  
[PDF Download](https://www.tzcert.go.tz/report/TZCERT-HON-26-0105-honeypot-report-3rd-august-2026/download)

**Threat-intelligence review date:** 2026-08-13
