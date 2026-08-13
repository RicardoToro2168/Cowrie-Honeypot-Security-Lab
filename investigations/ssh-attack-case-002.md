# Case 002 – RedTail Malware Deployment via SSH/SFTP

## Part 1: Initial Investigation and Triage

* **Investigation Type:** Honeypot / Malware Deployment
* **Sensor:** Cowrie SSH Honeypot
* **Platform:** Internet-Exposed Linux Honeypot
* **Date:** Aug 12, 2026
* **Attacker IP:** `130.12.x.x`
* **Cowrie Session ID(s):** `ea2321adb86b`
* **Disposition:** Malicious Activity Confirmed
* **Working Attribution:** RedTail-related cryptomining campaign — High Confidence

---

### Executive Summary

Cowrie detected an attacker using SFTP to upload seven files to the honeypot during an SSH session:

* `clean.sh`
* `setup.sh`
* `redtail.x86_64`
* `redtail.i686`
* `redtail.riscv`
* `redtail.arm7`
* `redtail.arm8`

Following the file transfers, the attacker issued a chained command that attempted to execute the cleanup and installation scripts, delete those scripts after execution, establish SSH persistence by replacing the user's `authorized_keys` file, protect that file using Linux extended attributes, enumerate system information, and print an encoded `auth_ok` completion marker.

Initial analysis of the two shell scripts showed that `clean.sh` attempts to remove competing cryptomining activity and other persistence mechanisms, while `setup.sh` identifies the victim's CPU architecture, searches for a suitable executable filesystem location, selects the appropriate architecture-specific payload, executes it under a randomized hidden filename, and deletes the original `redtail.*` files.

The observed SSH persistence command contains the key comment `rsa-key-20230629`. The same SSH public key and persistence sequence have previously been documented during RedTail infections observed by the SANS Internet Storm Center.

Additionally, all five captured architecture-specific binary hashes appeared in an August 2026 TZ-CERT honeypot report, where they were classified using cryptocurrency-miner or miner-associated malware labels.

Based on the combined Cowrie telemetry, script behavior, file naming, SSH persistence mechanism, exact public-key correlation, and external threat-intelligence matches, this activity was assessed with high confidence as a RedTail-related cryptomining deployment attempt.

Binary reverse engineering and deeper analysis of the captured ELF payloads were intentionally deferred to **Part 2: Malware Analysis**.

---

### 1. Investigation Scope

The purpose of this phase was to determine:

* What activity triggered the Cowrie alert.
* What files the attacker transferred.
* What actions the attacker attempted after the transfer.
* Whether persistence or defense-evasion mechanisms were present.
* Whether the activity correlated with a known malware campaign.
* Which indicators and artifacts should be preserved for subsequent malware analysis.

This phase did not include execution, reverse engineering, disassembly, or dynamic sandbox analysis of the RedTail ELF binaries.
The investigation is based primarily on Cowrie telemetry and captured artifacts. Activity observed inside the honeypot should not by itself be interpreted as evidence that the underlying VPS operating system was compromised.

---

### 2. Initial Alert

Cowrie generated SFTP file-transfer alerts showing that the same source IP uploaded the following files:

```text
SFTP Uploaded file "setup.sh"
SFTP Uploaded file "redtail.x86_64"
SFTP Uploaded file "redtail.i686"
SFTP Uploaded file "redtail.riscv"
SFTP Uploaded file "redtail.arm7"
SFTP Uploaded file "clean.sh"
SFTP Uploaded file "redtail.arm8"
```
The filenames immediately warranted investigation because the attacker transferred:

* Two shell scripts
* Five executable payloads
* Multiple CPU architecture variants
* Files explicitly using the name `redtail`


The presence of architecture-specific binaries suggested an automated deployment package designed to operate across multiple Linux hardware platforms.

---

### 3. Initial Attacker Command

After transferring the files, the attacker initiated the following sequence:

```bash
chmod +x clean.sh;
sh clean.sh;
rm -rf clean.sh;

chmod +x setup.sh;
sh setup.sh;
rm -rf setup.sh;

mkdir -p ~/.ssh;
chattr -ia ~/.ssh/authorized_keys;

echo "<ATTACKER KEY PUBLIC SSH> rsa-key-20230629" > ~/.ssh/authorized_keys;

chattr +ai ~/.ssh/authorized_keys;

uname -a;

echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"
```

For readability, the full SSH public-key material has been abbreviated in the command above. The original command was retained separately as evidence.

The command establishes a clear sequence of attacker objectives:
**Execution** → **Cleanup** → **Payload Installation** → **Persistence** → **Persistence Protection** → **System Discovery** → **Completion Confirmation**

---

### 4. Command Analysis

#### 4.1 Cleanup Script Execution

The attacker first executed:

```bash
chmod +x clean.sh
sh clean.sh
rm -rf clean.sh
```

The use of `sh clean.sh` launches the cleanup routine, while the subsequent deletion removes the deployment script after use.

Review of the captured `clean.sh` showed that the script attempts to:

* Stop and disable `c3pool_miner`
* Stop and disable `bot.service`
* Remove suspicious entries from user and system cron files
* Remove immutable and append-only attributes before altering files
* Inspect multiple standard cron locations
* Remove cron entries containing strings commonly associated with downloaders, reverse shells, temporary-file execution, and script-based malware
* Purge files from `/tmp`, `/var/tmp`, and `/dev/shm` when doing so would not remove its own working directory

Examples of strings removed from cron entries include:

* `wget`
* `curl`
* `/dev/tcp`
* `/tmp`
* `.sh`
* `nc`
* `bash -i`
* `sh -i`
* `base64 -d`

The filtering is indiscriminate and could remove legitimate entries matching those expressions. However, in the context of the remaining activity, the behavior is consistent with an attacker attempting to remove competing malware and persistence mechanisms before deploying its own payload.

MITRE ATT&CK specifically notes that some cryptocurrency-mining malware kills competing malware processes to prevent competition for system resources.

---

### 5. Payload Installation Script

The attacker then executed:

```bash
chmod +x setup.sh
sh setup.sh
rm -rf setup.sh
```

Initial static review of `setup.sh` showed that the script performs several deployment functions.

#### 5.1 Architecture Discovery

The script obtains processor architecture using:

```bash
ARCH=$(uname -mp)
```

It then maps detected architectures to one of five payloads:

| Detected Architecture | Selected Payload |
| :--- | :--- |
| `x86_64` / `amd64` | `redtail.x86_64` |
| `i386` – `i686` | `redtail.i686` |
| `armv8` / `aarch64` | `redtail.arm8` |
| `armv7` | `redtail.arm7` |
| `RISC-V` | `redtail.riscv` |

The architecture-selection logic directly confirms that the transferred files were intended as alternative versions of the same deployment payload for different hardware platforms.

The use of `uname` to identify host or processor characteristics is consistent with **MITRE ATT&CK T1082 – System Information Discovery**.

---

### 6. Execution-Location Discovery

The setup script does not immediately execute its payload from the upload directory.
Instead, it first attempts to identify filesystems mounted with the `noexec` option:

```bash
findmnt -rn -O noexec -o TARGET
```

If `findmnt` is unavailable, it examines `/proc/mounts` as a fallback.
The script then searches the system for directories:

```bash
find / -type d -user $(whoami) -perm -u=rwx ...
```

Candidate directories must be accessible by the compromised user and are filtered to avoid locations the script determined were mounted `noexec`. `/proc` and parts of `/tmp` are also excluded during the initial search.

The use of `find` to enumerate suitable locations is consistent with **T1083 – File and Directory Discovery**. MITRE describes this technique as searching or enumerating filesystem locations to inform subsequent adversary actions.

---

### 7. Writable-Directory Validation

For each candidate location, the script tests whether it can successfully create files:

```bash
touch .testfile
```

It then attempts to create an approximately 2 MB test file using either:

```bash
dd if=/dev/zero of=.testfile2 bs=2M count=1
```
or:
```bash
truncate -s 2M .testfile2
```

If successful, the test files are removed and the `redtail.*` payload set is moved into that directory.

This demonstrates that the deployment process does not rely solely on filesystem permissions. It actively verifies that a candidate directory is writable and capable of holding the payload before proceeding.

---

### 8. Randomized Hidden Executable

Instead of retaining the recognizable `redtail` filename, `setup.sh` generates a randomized hidden filename:

```bash
FILENAME=".$(get_random_string)"
```

The script attempts to generate the random string using:

* OpenSSL-generated randomness
* `/dev/urandom`
* The shell `$RANDOM` variable
* `redtail` as a final fallback

The leading period causes the resulting filename to be hidden under normal Linux directory listings.

For a successfully identified architecture, the selected RedTail binary is copied into the randomized file:

```bash
cat redtail.$ARCH > $FILENAME
chmod +x $FILENAME
./$FILENAME ssh
```

The original architecture-specific files are later deleted:

```bash
rm -rf redtail.*
```

The purpose and internal behavior of the resulting executable were not examined during this phase and are reserved for Part 2.

---

### 9. SSH Persistence

After executing the deployment scripts, the attacker attempted to establish persistent SSH access:

```bash
mkdir -p ~/.ssh
chattr -ia ~/.ssh/authorized_keys
echo "<ATTACKER KEY PUBLIC> rsa-key-20230629" > ~/.ssh/authorized_keys
chattr +ai ~/.ssh/authorized_keys
```

This sequence:

1. Creates the `.ssh` directory if necessary.
2. Removes immutable and append-only attributes from `authorized_keys`.
3. Replaces the contents of the file with an attacker-controlled SSH key.
4. Reapplies both the append-only and immutable attributes.

If performed against a real Linux account with sufficient permissions, possession of the corresponding private key could allow the attacker to authenticate without knowing the account password.

MITRE ATT&CK defines modification of `authorized_keys` for persistent access as **T1098.004 – Account Manipulation: SSH Authorized Keys**.

The subsequent use of:

```bash
chattr +ai ~/.ssh/authorized_keys
```
would also make normal modification or deletion of the persistence file more difficult.

---

### 10. Threat-Intelligence Correlation

One of the strongest indicators discovered during triage was the SSH-key comment:

`rsa-key-20230629`

SANS Internet Storm Center reporting on RedTail activity documented the same SSH public key and essentially the same sequence of:

```bash
chattr -ia authorized_keys
# write attacker SSH key
chattr +ai authorized_keys
uname -a
```

during observed RedTail compromises.

The correlation is significant because it connects the current Cowrie activity to previously documented RedTail deployment behavior independently of the `redtail.*` filenames.

---

### 11. Payload Hash Correlation

Cowrie preserved SHA-256 hashes for the uploaded files.

#### Scripts
* **`clean.sh`**  
  `3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892`
* **`setup.sh`**  
  `1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d`

#### Architecture-Specific Payloads
* **`redtail.x86_64`**  
  `f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987`
* **`redtail.i686`**  
  `8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70`
* **`redtail.arm7`**  
  `d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141`
* **`redtail.arm8`**  
  `d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e`
* **`redtail.riscv`**  
  `3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39`

A TZ-CERT honeypot report covering July 27 through August 2, 2026 independently reported all five of the binary SHA-256 values among its top observed malware samples. The report applied detection labels including `miner.malxmr`, `trojan.malxmr`, and `trojan.abminer` to the matching samples.

Because antivirus naming varies between vendors and detection engines, those labels were treated as supporting evidence rather than definitive malware-family identification.

---

### 12. Completion Marker

The attacker's final command was:

```bash
echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"
```

Decoding the hexadecimal values produces:

`auth_ok`

This does not establish network command-and-control communication because the command only prints text to the current shell.
Within the observed sequence, it is most reasonably interpreted as an automation marker indicating that the scripted deployment process had reached its expected completion point.

---

### 13. Artifact Deletion

The attacker deliberately removed several files after using them:

```bash
rm -rf clean.sh
rm -rf setup.sh
```

The setup script additionally removes:

```bash
rm -rf redtail.*
```

This would reduce the number of recognizable installation artifacts remaining on a successfully compromised system.

MITRE ATT&CK classifies adversary deletion of files associated with intrusion activity as **T1070.004 – Indicator Removal: File Deletion**.

---

### 14. MITRE ATT&CK Mapping

| Observed Activity | MITRE ATT&CK Technique | Evidence |
| :--- | :--- | :--- |
| SFTP upload of scripts and executables | **T1105 – Ingress Tool Transfer** | Seven files transferred into the Cowrie environment |
| Execution of `clean.sh` and `setup.sh` | **T1059.004 – Unix Shell** | Attacker explicitly invoked both using `sh` |
| `uname -mp` and `uname -a` | **T1082 – System Information Discovery** | Architecture and system-information collection |
| Filesystem search using `find` | **T1083 – File and Directory Discovery** | Search for suitable writable/executable directories |
| Modification of `~/.ssh/authorized_keys` | **T1098.004 – SSH Authorized Keys** | Attacker-controlled SSH key inserted for persistence |
| Removal of scripts and payload files | **T1070.004 – File Deletion** | `clean.sh`, `setup.sh`, and `redtail.*` deleted |
| Cryptomining-related payload deployment | **T1496.001 – Compute Hijacking** | Supported by script behavior and independent malware-hash correlation |

MITRE defines T1105 as transferring adversary tools or files into a compromised environment, while T1059.004 covers adversary use of Unix shells and shell scripts for execution.

The cryptomining assessment is consistent with T1496.001, which covers unauthorized use of compromised compute resources, including cryptocurrency mining. MITRE also specifically notes that mining malware may terminate competitors to monopolize resources.

---

### 15. Indicators of Compromise

#### Network Indicator
* **Source IP:** `130.12.x.x`

#### File Indicators
| File | SHA-256 |
| :--- | :--- |
| `clean.sh` | `3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892` |
| `setup.sh` | `1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d` |
| `redtail.x86_64` | `f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987` |
| `redtail.i686` | `8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70` |
| `redtail.arm7` | `d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141` |
| `redtail.arm8` | `d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e` |
| `redtail.riscv` | `3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39` |

#### SSH Indicator
* **SSH key comment:** `rsa-key-20230629`

#### File/Path Indicators
* `~/.ssh/authorized_keys`
* `/tmp`
* `/var/tmp`
* `/dev/shm`

*Note: A successfully infected system may also contain a hidden executable with a randomized alphanumeric filename generated by `setup.sh`; therefore, `.redtail` should not be treated as the only possible installed filename.*

---

### 16. Evidence Integrity Note

Cowrie-recorded SHA-256 hashes represent the original files transferred by the attacker.

For safe local review, copies of `clean.sh` and `setup.sh` were subsequently modified by the analyst because local antivirus controls prevented the original scripts from being saved normally.

The analyst modifications consisted of:
1. Altering the shell interpreter line; and
2. Inserting a comment identifying content removed or changed to permit saving.

As a result, the locally reviewed script copies no longer produce the original Cowrie SHA-256 hashes.

The original Cowrie-generated hashes have therefore been retained as the authoritative hashes for the attacker-uploaded artifacts.

This distinction is documented to preserve the integrity and provenance of the evidence used in the investigation.

---

### 17. Assessment

#### Finding
**Malicious malware deployment activity was confirmed.**

The attacker used an authenticated SSH/SFTP session to transfer a multiarchitecture malware deployment package and initiate an automated installation sequence.

The deployment workflow attempted to:
* Eliminate competing cryptomining activity and persistence
* Identify victim architecture
* Locate a usable execution directory
* Deploy the architecture-compatible executable
* Conceal the payload using a randomized hidden filename
* Delete installation artifacts
* Replace the user's SSH authorized-key configuration with an attacker-controlled key
* Protect the persistence mechanism from modification
* Confirm completion of the deployment sequence

#### Attribution
**RedTail-related malware campaign — High Confidence**

This assessment is based on the convergence of:
* `redtail.*` payload naming
* RedTail-specific deployment logic
* Cryptominer competitor-removal behavior
* Architecture-specific payload selection
* The exact `rsa-key-20230629` SSH-key indicator previously observed in RedTail attacks
* The same SSH persistence workflow documented in previous RedTail incidents
* Independent public reporting of the exact captured binary hashes as mining-related malware

The available evidence supports identification of the malware campaign but does not support attribution of the individual intrusion to a specific human operator, criminal organization, or nation-state actor.

---

### 18. Limitations

Several conclusions were deliberately withheld during this phase.

The investigation did not yet determine:
* The internal functionality of the ELF payloads
* Whether the binaries are packed or obfuscated
* Embedded command-and-control infrastructure
* Mining-pool addresses
* Cryptocurrency wallet information
* Process names created by the binaries
* Additional persistence implemented by the binaries
* Propagation functionality
* The meaning of the `ssh` argument passed to the payload
* Network communications initiated by the binaries
* Whether functionality differs between the five architecture variants

These questions require examination of the actual malware samples and will be addressed separately.

Additionally, the observed activity occurred within a Cowrie honeypot. Nothing reviewed during this phase establishes that the attacker escaped the honeypot or successfully executed code on the underlying VPS operating system.

---

### 19. Conclusion

This investigation demonstrates the value of an internet-facing honeypot beyond simply recording authentication attempts.

Cowrie captured a complete post-authentication malware deployment workflow, including file transfer, execution commands, cleanup behavior, architecture discovery, persistence attempts, artifact deletion, and the malware samples themselves.

Initial triage identified a high-confidence RedTail-related cryptomining deployment and preserved five architecture-specific binaries for additional examination.

Rather than executing unknown files during the initial investigation, the artifacts were preserved and hashed so that subsequent analysis could occur in a controlled environment.

The next phase of the investigation will transition from incident triage to malware analysis.

---

## Part 2 – Malware Analysis

The next investigation phase will examine the captured RedTail binaries beginning with:

**`redtail.x86_64`**
* **SHA-256:** `f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987`

Part 2 will focus on static analysis before any controlled dynamic analysis is considered, including:
* ELF metadata
* Architecture and linking information
* Strings and embedded configuration
* Packing or obfuscation indicators
* Network indicators
* Mining-related configuration
* Persistence functionality
* Process behavior
* Functionality associated with the `ssh` execution argument
* Comparison among the architecture-specific variants

---

## Evidence

Supporting evidence collected during this investigation is available in the
[`evidence`](../evidence/ssh-attack-case-002) directory.

Evidence includes:

- Sanitized Cowrie session telemetry
- SFTP file-transfer events
- Original attacker command
- SHA-256 hashes of all transferred artifacts
- Analyst-reviewed copies of `clean.sh` and `setup.sh`


> **Malware Handling Notice:** The executable RedTail samples are intentionally
> excluded from this public repository. SHA-256 hashes and analysis artifacts
> are provided instead. Original malware specimens are retained separately for
> controlled analysis.

The shell-script copies included in this repository were modified by the analyst
to permit safe storage due to endpoint antivirus detection. Their original
Cowrie-recorded SHA-256 values are preserved in `evidence/hashes/sha256.txt`,
and all modifications are documented in `evidence/scripts/README.md`.

---

## References

1. MITRE ATT&CK – [SSH Authorized Keys (T1098.004)](https://attack.mitre.org/techniques/T1098/004)
2. MITRE ATT&CK – [Ingress Tool Transfer (T1105)](https://attack.mitre.org/techniques/T1105)
3. MITRE ATT&CK – [Unix Shell (T1059.004)](https://attack.mitre.org/techniques/T1059/004)
4. MITRE ATT&CK – [System Information Discovery (T1082](https://attack.mitre.org/techniques/T1082)
5. MITRE ATT&CK – [File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083)
6. MITRE ATT&CK – [File Deletion (T1070.004)](https://attack.mitre.org/techniques/T1070/004)
7. MITRE ATT&CK – [Compute Hijacking (T1496.001)](https://attack.mitre.org/techniques/T1496/001)
8. SANS Internet Storm Center – [RedTail / Linux SSH honeypot investigations](https://isc.sans.edu/diary/32024)
9. Tanzania Computer Emergency Response Team **PDF** – [Honeypot Weekly Report, July 27–August 2, 2026 *PDF Download*](https://www.tzcert.go.tz/report/TZCERT-HON-26-0105-honeypot-report-3rd-august-2026/download)
