# Malformed SSH Authentication Probe — Suspected CVE-2018-15473 Username Enumeration

## Executive Summary

An Internet-facing **Cowrie SSH honeypot** generated an alert after receiving a malformed SSH public-key authentication request containing an unusual hexadecimal payload.

Manual analysis identified a structurally recognizable SSH authentication request using the `publickey` method, followed by an apparent protocol-format violation: the `boolean` field required by the SSH public-key authentication protocol was missing immediately before the `ssh-rsa` algorithm field.

This behavior is strongly consistent with probing associated with **CVE-2018-15473**, an OpenSSH username-enumeration vulnerability affecting OpenSSH through version 7.7. The vulnerability allowed differences in authentication-request parsing to reveal whether a supplied username existed on the target system.

The observed packet closely matches the malformed request structure used to trigger this parsing behavior. However, the available telemetry does not identify the exact attack tool or prove that a specific public exploit implementation was used.

* **Assessment:** Likely OpenSSH username-enumeration probe consistent with CVE-2018-15473.
* **Impact:** No evidence of compromise to the underlying VPS was identified. The traffic was directed to the Cowrie honeypot on `TCP/22`, not the administrative SSH service on `TCP/22022`.

---

## Incident Summary

| Field | Value |
| :--- | :--- |
| **Sensor** | Cowrie SSH Honeypot |
| **Destination Service** | SSH / `TCP/22` |
| **Source IP** | `[REDACTED]` |
| **Source Port** | `59124` |
| **Timestamp** | `Aug 9, 2026 @ 18:57:32.979 UTC' |
| **Alert Type** | Malformed SSH traffic / possible exploit |
| **Suspected Activity** | SSH username enumeration |
| **Related Vulnerability** | CVE-2018-15473 |
| **Confidence** | Moderate |
| **Host Compromise Observed** | No evidence identified |

### Confidence Assessment

Two conclusions were assigned separate confidence levels:

1. **High confidence:** The captured SSH public-key authentication request is malformed.
2. **Moderate confidence:** The malformed request was intentionally constructed to probe behavior associated with CVE-2018-15473.

> **Analyst Note:** This distinction avoids attributing the activity to a specific exploit tool based only on packet structure.

---

## Detection

Cowrie generated an alert after receiving malformed data during SSH authentication. The captured hexadecimal payload began with:

```text
0000000c4e4c35785544705632785261
0000000e7373682d636f6e6e656374696f6e
000000097075626c69636b6579
000000077373682d727361
00000097...
```
> **Triage Tooling:** Raw hexadecimal telemetry was parsed using **CyberChef** to extract human-readable SSH protocol structures and verify field offsets.
> 
> **CyberChef Recipe:** `From Hex ('Auto')` ➔ `To Hexadump`

Converting the hexadecimal values into their encoded SSH fields revealed recognizable protocol elements:

* `NL5xUDpV2xRa`
* `ssh-connection`
* `publickey`
* `ssh-rsa`

The presence of these values indicated that the payload was associated with an SSH user-authentication request using public-key authentication.

---

## Packet Analysis

SSH strings are encoded using a four-byte length field followed by the string data. The beginning of the captured payload can be parsed as follows:

| Hexadecimal | Interpretation |
| :--- | :--- |
| `0000000c` | String length: 12 bytes |
| `4e4c35785544705632785261` | Username: `NL5xUDpV2xRa` |
| `0000000e` | String length: 14 bytes |
| `7373682d636f6e6e656374696f6e` | Service: `ssh-connection` |
| `00000009` | String length: 9 bytes |
| `7075626c69636b6579` | Authentication method: `publickey` |
| `00000007` | String length: 7 bytes |
| `7373682d727361` | Public-key algorithm: `ssh-rsa` |
| `00000097` | Following public-key blob length |

At this point, the packet appeared syntactically reasonable until its structure was compared against the SSH authentication protocol specification.

### Expected SSH Public-Key Request

RFC 4252 defines a public-key authentication query with the following structure:

```text
SSH_MSG_USERAUTH_REQUEST
    string    username
    string    service name
    string    "publickey"
    boolean   FALSE
    string    public key algorithm
    string    public key blob
```

The critical field for this investigation is **`boolean FALSE`**. A one-byte boolean value must occur between the `publickey` method name and the public-key algorithm string. 

A correctly structured sequence should logically resemble:

```text
username
ssh-connection
publickey
FALSE
ssh-rsa
<public-key-blob>
```

### Observed Malformation

The captured request instead contained:

```text
username
ssh-connection
publickey
ssh-rsa
<public-key-blob>
```

**The expected boolean was absent.** At the byte level, a valid unsigned public-key query would contain a sequence conceptually similar to:

```text
00                # boolean FALSE
00 00 00 07       # length of "ssh-rsa"
73 73 68 2d 72 73 61
```

The captured payload instead moved directly from `publickey` into:

```text
00 00 00 07       # length of "ssh-rsa"
73 73 68 2d 72 73 61
```

If an SSH parser interprets the first `00` byte from `00000007` as the required boolean, the parser becomes misaligned. The following four bytes are then interpreted as the algorithm-string length (`00 00 07 73` instead of `00 00 00 07`), producing an invalid length relative to the remaining packet and causing parsing to fail.

The packet therefore appears to be **deliberately malformed** at a specific point in the SSH public-key authentication structure rather than simply corrupted random traffic.

---

## CVE-2018-15473 Correlation

CVE-2018-15473 is an OpenSSH username-enumeration vulnerability affecting OpenSSH versions through 7.7. The vulnerability resulted from differences in how authentication requests were processed depending on whether the supplied username was valid.

For an invalid username, vulnerable OpenSSH implementations could exit authentication processing before completely parsing portions of the authentication request. A valid username could cause additional parsing to occur. An attacker could exploit this difference by intentionally sending a malformed authentication request.

```text
                Malformed Authentication Request
                            │
                   ┌────────┴────────┐
                   │                 │
             Invalid User       Valid User
                   │                 │
             Early rejection    Further parsing
                   │                 │
                   │          Malformed field reached
                   │                 │
                   └────────┬────────┘
                            │
                Observable response difference
                            │
                            ▼
                   Username Enumeration
```

OpenSSH 7.8 later included a fix intended to eliminate observable differences in request parsing that could reveal whether a target user was valid. The structure of the packet captured by Cowrie is notable because the malformed field occurs within the public-key authentication request where parser behavior can be manipulated.

---

## Why This Resembles a CVE-2018-15473 Probe

1. **Public-Key Authentication Was Selected:** The packet explicitly contains `publickey`. The vulnerability involves OpenSSH public-key authentication request parsing.
2. **Contains a Valid-Looking RSA Key Structure:** Immediately following the malformed portion, the payload includes `ssh-rsa` and an encoded RSA public-key blob, suggesting the request was not random noise.
3. **Malformation Occurs at a Specific Protocol Field:** The expected boolean immediately following `publickey` is absent, while the remainder of the packet remains structured. This is consistent with intentional manipulation rather than generalized network packet corruption.
4. **Matches Underlying Mechanism:** CVE-2018-15473 relies on differences in how malformed authentication requests are parsed for valid versus invalid usernames. The captured request contains the precise type of parser-disrupting condition required.

---

## Attribution Limitations

The evidence supports correlation with the vulnerability, but it does not prove a specific exploit implementation was used. The following could not be established from the available telemetry:

* The exact scanning or exploitation tool.
* Whether the source used a public proof-of-concept (PoC) script.
* Whether the source specifically identified the target as running a vulnerable OpenSSH version.
* Whether any tested username would have been considered valid by a real OpenSSH server.
* Whether the same source performed successful username enumeration against another system.
* **Absence of Full PCAP Telemetry:** Because Cowrie operates at the application/honeypot layer, logging was limited to application-level payload buffers. Transport-layer TCP stream reassembly and packet-level flags could not be independently inspected without a raw packet capture (`.pcap`).

For these reasons, the event is classified as **"Likely OpenSSH username-enumeration probing consistent with CVE-2018-15473"** rather than confirmed exploitation, preserving analytical integrity.

---

## Threat Intelligence & CTI Enrichment

To contextualize the source IP (`103.114.x.x`), telemetry was cross-referenced against external Threat Intelligence platforms to determine actor intent and broader infrastructure patterns.

**CTI Enrichment Date:** August 9, 2026
| CTI Platform | Intelligence Finding | Context & Classification |
| :--- | :--- | :--- |
| **AbuseIPDB** | 90% Abuse Confidence Score (>80 from 23 distinct sources) | Flagged globally for aggressive SSH brute-force and port scanning. |
| **GreyNoise** | Classified as **"Malicious"**  | Associated by GreyNoise with activity consistent with NoaBot botnet. |
| **AlienVault OTX** | Associated with 3 Threat Pulses | Linked to SSH bruteforce hosts and botnets. |

> **CTI Takeaway:** External reputation data indicates that the source infrastructure has previously been associated with malicious SSH scanning and botnet activity. This context increases confidence that the observed event was part of automated Internet-wide reconnaissance rather than activity uniquely directed at this honeypot; however, source-IP reputation alone cannot conclusively establish attacker intent.

---

## Scope and Impact Analysis

The probe was received by the Cowrie honeypot exposed on `TCP/22`. The legitimate VPS administrative SSH service is separately configured on `TCP/22022`.

Administrative SSH is protected by:
* **UFW source-IP allowlisting** (only trusted management sources permitted)
* **Key-based authentication**
* **Network separation** from the Internet-facing Cowrie service
* **Independent host-level monitoring**

No evidence from this event indicated that the probe reached or affected the real administrative SSH service. The event represented adversary telemetry collected by the honeypot rather than evidence of compromise to the underlying VPS.

---

## Analyst Assessment

```text
Malformed SSH Traffic
        │
        ▼
Malformed Public-Key Authentication Request
        │
        ▼
Protocol Structure Analysis
        │
        ▼
Known Vulnerability Correlation
        │
        ▼
Suspected Username Enumeration
```

The payload contained enough valid SSH structure to identify a username field, the `ssh-connection` service, the `publickey` authentication method, and an RSA public-key blob. The primary structural anomaly was the missing boolean field required by RFC 4252.

> **Conclusion:** The source likely sent an intentionally malformed SSH public-key authentication request designed to test username-dependent server behavior. The packet structure is strongly consistent with CVE-2018-15473-style OpenSSH username enumeration.
> 
> **Analytical Confidence:** Moderate  
> **Host Integrity:** No compromise detected.

---

## Detection Engineering & Mitigation Outputs

To transition this analysis from reactive triage to proactive defense, customized detection rules and network mitigation controls were developed based on the observed payload characteristics.

### 1. Custom Wazuh Detection Rule
A custom Wazuh rule was implemented to escalate Cowrie malformed-packet and exploit-related events for analyst investigation.

```xml
<group name="cowrie,ssh_recon,">
  <!-- Custom rule targeting malformed SSH publickey probing -->
  <rule id="100107" level="12">
    <if_sid>100100</if_sid>
    <field name="eventid" type="pcre2">^cowrie\.client\.malformed_packet$|^cowrie\.telnet\.exploit_(attempt|success)$</field>
    <description>Cowrie detected malformed traffic or an exploit attempt from $(src_ip).</description>
    <mitre>
      <id>T1595.002</id> <!-- Active Scanning: Vulnerability Scanning -->
    </mitre>
  </rule>
</group>
```

### 2. Network-Level Automated Mitigation (IPTables / UFW)
> **Architectural Note:** This mitigation control was intentionally **not** applied to the Cowrie honeypot interface (`TCP/22`). Blocking or rate-limiting traffic on a honeypot undermines its core objective—capturing full threat actor techniques, payload variations, and post-exploitation attempts. However, this control represents the baseline network-hardening standard for production SSH endpoints.

Because CVE-2018-15473 requires sequential SSH handshake attempts to enumerate usernames, rate-limiting incoming SSH TCP connections on public edge interfaces using `netfilter` (`xt_recent`) reduces the throughput of automated enumeration.

```bash
# Limit new SSH connections to 4 attempts per 60 seconds per IP address
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
```

### 3. Automated PCAP Ring-Buffer & Alert-Triggered Capture

To overcome the lack of raw packet telemetry in application-only honeypot logs, a rolling network packet capture and automated preservation pipeline is **planned**:

* **Continuous Buffer (`Tshark`):** `tshark` runs as a background systemd service capturing raw network traffic into a rolling ring buffer (e.g., ten 60-second `.pcap` files) on the host interface.
* **Alert-Driven Preservation (`Wazuh Active Response`):** When Wazuh fires Rule `100107` (Malformed SSH Probe), a custom Active Response script executes immediately, preserving the current PCAP buffer slice and moving it to permanent evidence storage before ring-buffer overwrite occurs.

---

## Defensive Takeaways

* **Protocol Errors Can Be Security-Relevant:** Malformed traffic should not automatically be dismissed as scanner noise or application errors. Protocol-format violations may be intentional mechanisms used to exercise vulnerable parsing behavior.
* **Raw Telemetry Context:** Decoding raw hexadecimal payload data exposed enough SSH structure to transition the investigation from a generic anomaly to a specific threat actor technique.
* **Confidence Language Matters:** Separating observed facts, technical interpretation, and analytical assessment prevents overstating threat findings to stakeholders.
* **Honeypot Isolation:** Keeping administrative SSH on a separate, source-restricted port (`TCP/22022`) prevented public exposure while collecting threat intelligence on standard ports (`TCP/22`).

---

## Production Response Considerations

If equivalent traffic were observed against a production SSH server, the investigation workflow would include:

1. **Patch Verification:** Verify OpenSSH version and vendor patch status for CVE-2018-15473.
2. **Telemetry Audit:** Review authentication logs for repeated requests targeting multiple usernames from the source IP.
3. **Correlation:** Cross-reference the source IP with threat intelligence feeds and other edge-device logs for scanning or brute-force behavior.
4. **Follow-on Tracking:** Monitor for subsequent password-guessing or secondary exploit attempts.
5. **Access Control:** Enforce network-level restrictions (e.g., UFW/IPtables allowlists, VPN requirements) for SSH management interfaces.

---

## Evidence Structure

Supporting sanitized evidence for this investigation is maintained under:

```text
evidence/
└── attack-case-001/
    ├── wazuh-alert.png
    ├── cowrie-event.json
    └── packet-analysis.txt
```

*(Sensitive operational information, including public infrastructure addresses and unnecessary identifying metadata, has been sanitized.)*

---

## References

* **RFC 4252:** [The Secure Shell (SSH) Authentication Protocol](https://datatracker.ietf.org/doc/html/rfc4252)
* **NVD:** [CVE-2018-15473 Detail](https://nvd.nist.gov/vuln/detail/CVE-2018-15473)
* **OpenSSH:** [OpenSSH 7.8 Release Notes](https://www.openssh.com/txt/release-7.8)

---

[← Back to Project README](../README.md)
