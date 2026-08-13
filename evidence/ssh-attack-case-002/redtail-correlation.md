# RedTail Behavioral Correlation

## Purpose

This file documents external threat-intelligence correlations used during **SSH Attack Case 002**.  
The goal is to compare behavior observed directly in Cowrie with previously documented RedTail activity.

This correlation is supporting evidence only. It does not, by itself, identify the individual operator behind the observed source IP.

---

## Internal Evidence Observed

Cowrie recorded an SSH/SFTP session in which the attacker:

- Uploaded `clean.sh` and `setup.sh`.
- Uploaded architecture-specific payloads named:
  - `redtail.x86_64`
  - `redtail.i686`
  - `redtail.arm7`
  - `redtail.arm8`
  - `redtail.riscv`
- executed a command that would
  - Execute `clean.sh` and delete it.
  - Executed `setup.sh` and delete it.
  - Created `~/.ssh` if it did not already exist.
  - Remove immutable and append-only attributes from `~/.ssh/authorized_keys`.
  - Replace `authorized_keys` with an attacker-controlled SSH public key.
  - Used the SSH key comment `rsa-key-20230629`.
  - Reapplly immutable and append-only attributes to `authorized_keys`.
  - Execute `uname -a`.
  - Print the hexadecimal-encoded completion marker `auth_ok`.

The captured `clean.sh` also targeted `c3pool_miner` and removed cron entries matching common downloader, reverse-shell, temporary-file, and script-execution patterns.

The captured `setup.sh` identified the host architecture, selected a matching `redtail.*` payload, searched for a suitable execution location, used a hidden randomized executable name, executed the selected payload, and deleted the original `redtail.*` files.

---

## External Correlation 1 — SANS ISC, 2024

**Source:** SANS Internet Storm Center  
**Title:** Analysis of “redtail” File Uploads to ICS Honeypot, a Multi-Architecture Coin Miner  
**Published:** May 23, 2024  
**URL:**  
https://isc.sans.edu/diary/30950

### Relevant Correlations

The SANS investigation documented an SSH honeypot intrusion that included:

- Uploads named `redtail.arm7`, `redtail.arm8`, `redtail.i686`, `redtail.x86_64`, and `setup.sh`.
- Architecture detection using `uname -mp`.
- Selection and execution of the architecture-specific RedTail payload.
- Deletion of the original `redtail.*` payloads.
- Modification of `~/.ssh/authorized_keys`.
- The same SSH public key used in this investigation, including the comment:
  - `rsa-key-20230629`
- Removal and reapplication of immutable/append-only attributes with `chattr`.
- Execution of `uname -a`.

### Assessment

The combination of the RedTail filenames, multi-architecture deployment logic, and exact SSH persistence key is highly consistent with the activity observed in SSH Attack Case 002.

---

## External Correlation 2 — SANS ISC, 2025

**Source:** SANS Internet Storm Center  
**Title:** Examining Redtail: Analyzing a Sophisticated Cryptomining Malware and its Advanced Tactics  
**Published:** January 9, 2025  
**URL:**  
https://isc.sans.edu/diary/31568

### Relevant Correlations

This later RedTail investigation documented:

- Upload of `clean.sh`, `setup.sh`, and multiple `redtail.*` binaries.
- A cleanup stage targeting competing cryptocurrency-mining activity.
- Specific disabling/stopping of `c3pool_miner`.
- Deletion of `clean.sh` and `setup.sh` after execution.
- Creation/modification of `~/.ssh/authorized_keys`.
- Use of the same `rsa-key-20230629` SSH key.
- Use of `chattr` to protect the persistence file.
- Execution of `uname -a`.
- The same encoded `auth_ok` completion marker.

### Assessment

These behaviors materially match the deployment sequence observed in the Cowrie session. The presence of `clean.sh`, the `c3pool_miner` cleanup behavior, the exact SSH key indicator, and the `auth_ok` marker provide particularly strong behavioral correlation.

---

## External Correlation 3 — SANS ISC, 2025

**Source:** SANS Internet Storm Center  
**Title:** Anatomy of a Linux SSH Honeypot Attack: Detailed Analysis of Captured Malware  
**Published:** June 13, 2025  
**URL:**  
https://isc.sans.edu/diary/32024

### Relevant Correlations

The report preserves a Cowrie command sequence containing the same major stages observed in this investigation:

1. Execute and remove `clean.sh`.
2. Execute and remove `setup.sh`.
3. Create `~/.ssh`.
4. Remove immutable/append-only attributes from `authorized_keys`.
5. Write the same `rsa-key-20230629` SSH public key.
6. Reapply immutable/append-only attributes.
7. Run `uname -a`.
8. Print the encoded `auth_ok` marker.

The report also identifies the SSH key fingerprint as:

`SHA256:78gkKoLYeUW62etRipAiAw2jImcwCMnvC5BO9+3mOtY`

### Assessment

The close command-sequence match is a strong behavioral indicator that the activity in SSH Attack Case 002 belongs to the same or a closely related malware deployment pattern.

---

## Attribution Assessment

**Assessment:** RedTail-related cryptomining campaign  
**Confidence:** High

### Confidence Basis

The assessment is based on the convergence of multiple independent indicators:

- `redtail.*` payload naming.
- Multi-architecture payload deployment.
- RedTail-compatible installation logic.
- Competing-miner cleanup behavior.
- Exact `rsa-key-20230629` SSH key correlation.
- Matching `chattr` persistence-hardening sequence.
- Matching `uname -a` discovery behavior.
- Matching encoded `auth_ok` completion marker.
- Independent malicious/mining-related hash correlation documented separately in `hash-correlation.md`.

No single indicator is treated as conclusive by itself. The high-confidence assessment is based on the combined behavioral and indicator overlap.

---

## Attribution Limitation

This evidence supports identification of a **RedTail-related malware deployment pattern**. It does **not** establish that the current source IP is the same actor, infrastructure owner, botnet node, or operator described in the external reports.

No nation-state, criminal group, or named human operator is attributed in this investigation.

---

## Sources

1. SANS Internet Storm Center — Analysis of “redtail” File Uploads to ICS Honeypot  
   https://isc.sans.edu/diary/30950

2. SANS Internet Storm Center — Examining Redtail: Analyzing a Sophisticated Cryptomining Malware and its Advanced Tactics  
   https://isc.sans.edu/diary/31568

3. SANS Internet Storm Center — Anatomy of a Linux SSH Honeypot Attack: Detailed Analysis of Captured Malware  
   https://isc.sans.edu/diary/32024

**Threat-intelligence review date:** 2026-08-13
