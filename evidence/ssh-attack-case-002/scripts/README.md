# Script Evidence

This directory contains analyst-reviewed copies of the shell scripts uploaded during **SSH Attack Case 002**:

- `clean.sh.txt`
- `setup.sh.txt`

## Evidence Integrity

The copies in this directory are **not byte-for-byte identical to the original attacker-uploaded files**.

Minor modifications were made to permit safe local storage because antivirus controls blocked the original scripts. These changes included altering the shell interpreter line and adding a comment indicating that content was modified for storage.

The authoritative SHA-256 hashes recorded by Cowrie are:

```text
clean.sh
3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892

setup.sh
1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d
```

The original hashes are also preserved in:

[sha256.txt](hashes/sha256.txt)

**These script copies are provided for behavioral review only. The original attacker-uploaded artifacts are not distributed in this public repository.**
