# keyvaultdog 🔑🐕

**SSH key assets hound, in one file.** Inventory every key asset in `~/.ssh`, audit it against a fixed invariant set, diff against a fingerprint baseline, and draft rotations. Zero dependencies, read-only by default.

```bash
python3 keyvaultdog.py scan      # fingerprint inventory
python3 keyvaultdog.py audit     # invariant findings (KV001-KV012), exit 0/1/2
python3 keyvaultdog.py baseline save
python3 keyvaultdog.py audit --baseline ~/.keyvaultdog-baseline.json
python3 keyvaultdog.py rotate --key ~/.ssh/id_ed25519   # dry-run
```

Findings: directory/private-key permissions, missing passphrases, zombie public keys, over-age keys, plaintext known_hosts, baseline drift (new/vanished fingerprints).

Invariants: never prints key material; never prints known_hosts hostnames; never writes into the scanned directory; rotate without `--apply` writes nothing and `--apply` only adds files (old key untouched).

```bash
python3 selftest.py   # 30 cases, synthetic fixtures, expect PASS 30/30
```

MIT
