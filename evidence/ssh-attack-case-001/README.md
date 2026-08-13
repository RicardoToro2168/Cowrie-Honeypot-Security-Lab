# Evidence — SSH Attack Case 001

This directory contains sanitized supporting evidence for:

**Malformed SSH Authentication Probe — Suspected CVE-2018-15473 Username Enumeration**

Full investigation:

[View Investigation](../../investigations/ssh-attack-case-001.md)

---

## Evidence Contents

| Artifact                 | Description                                                                                           |
| :----------------------- | :---------------------------------------------------------------------------------------------------- |
| `cowrie-event.json`      | Sanitized Cowrie event containing the malformed SSH payload and associated event metadata.            |
| `cyberchef-decoding.png` | Screenshot showing hexadecimal decoding and identification of SSH protocol fields using CyberChef.    |
| `abuseipdb.png`          | AbuseIPDB enrichment for the observed source IP at the time of investigation.                         |
| `greynoise.png`          | GreyNoise classification and contextual information for the observed source infrastructure.           |
| `otx.png`                | AlienVault OTX threat-intelligence enrichment associated with the observed source IP.                 |

---

## Evidence Purpose

The artifacts in this directory support the analytical conclusions documented in the investigation.

The evidence was used to establish:

* The original alert originated from the Cowrie honeypot.
* The captured payload contained recognizable SSH authentication structures.
* The expected boolean field following the `publickey` authentication method was absent.
* The malformed request structure was consistent with behavior associated with CVE-2018-15473.
* External threat-intelligence sources provided additional context regarding the observed source infrastructure.
* No evidence from this event indicated compromise of the underlying VPS or administrative SSH service.

---

## Sanitization

The evidence has been reviewed before publication.

Sensitive or unnecessary operational information may be:

* Redacted
* Partially masked
* Replaced with non-functional placeholders
* Cropped from screenshots

Examples of information intentionally excluded include:

* Public infrastructure addresses where disclosure is unnecessary
* Trusted management IP addresses
* Authentication credentials
* Private keys
* Internal service URLs
* Wazuh credentials
* Unrelated host or account information

Sanitization is limited to information that is not required to understand or reproduce the analytical reasoning.

---

## Threat Intelligence Note

Threat-intelligence enrichment represents the information available at the time of the investigation.

**Enrichment date:** `2026-08-9`

Reputation scores, classifications, tags, and threat-intelligence associations may change over time as providers receive additional telemetry.

Source-IP reputation was used as **supporting context** and was not treated as conclusive proof of attacker identity, intent, or attribution.

---

## Evidence Limitations

A full packet capture (`.pcap`) was not available for this event.

The investigation therefore relied on:

* Cowrie application telemetry
* The captured malformed SSH payload
* Protocol-field analysis
* Wazuh alert data
* External threat-intelligence enrichment

Because raw packet capture was unavailable, TCP-level behavior and complete SSH stream reconstruction could not be independently validated.

Future improvements to the honeypot environment include maintaining a rolling packet-capture buffer so relevant traffic can be preserved when high-priority Wazuh alerts occur.

---

[← Back to Investigation](../../investigations/attack-case-001.md)

