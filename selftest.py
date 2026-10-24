#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keyvaultdog self-test — 17 cases, fixtures are all synthetic keys (ed25519_test_fixture_*).
Run: python3 selftest.py  → expect 'SELFTEST PASS 17/17'."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keyvaultdog.py")
PASS = []
FAIL = []


def run(args, fixture_dir=None):
    cmd = [sys.executable, TOOL] + args
    env = dict(os.environ)
    if fixture_dir:
        env["HOME"] = fixture_dir  # so ~ abbreviates inside fixture
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
    return r.returncode, r.stdout, r.stderr


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + ((" — " + detail) if (detail and not cond) else ""))


def gen_key(path, comment, passphrase=""):
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", passphrase, "-C", comment,
                    "-f", path, "-q"], check=True, capture_output=True, timeout=30)


def make_fixture(tcd):
    """Synthetic ~/.ssh: 1 good key, 1 zombie pub, 1 no-passphrase key w/ loose perm."""
    ssh = os.path.join(tcd, ".ssh")
    os.makedirs(ssh, mode=0o700, exist_ok=True)
    main_key = os.path.join(ssh, "id_ed25519")
    gen_key(main_key, "ed25519_test_fixture_main")
    old_pub = os.path.join(ssh, "id_ed25519_old.pub")
    gen_key(os.path.join(ssh, "id_ed25519_old"), "ed25519_test_fixture_old")
    os.remove(os.path.join(ssh, "id_ed25519_old"))          # zombie pub
    loose = os.path.join(ssh, "deploy_rsa_nopass")
    gen_key(loose, "ed25519_test_fixture_nopass")           # no passphrase
    os.chmod(loose, 0o664)                                  # loose perm
    ancient = time.time() - 400 * 86400                     # 400 days old → KV004
    os.utime(loose, (ancient, ancient))
    with open(os.path.join(ssh, "config"), "w") as f:
        f.write("Host example-alias\n  HostName example.invalid\n")
    os.chmod(ssh, 0o755)                                    # loose dir
    return ssh


def leak_probe(ssh, blob):
    """True if any private-key body line appears in tool output (I1 violation)."""
    for f in os.listdir(ssh):
        p = os.path.join(ssh, f)
        if not os.path.isfile(p) or f.endswith(".pub"):
            continue
        try:
            body = open(p, "rb").read()
        except OSError:
            continue
        if b"PRIVATE KEY" in body:
            lines = body.split(b"\n")
            if len(lines) > 2 and lines[1][:48].decode("latin1") in blob:
                return True
    return False


def main():
    tcd = tempfile.mkdtemp(prefix="kvd-selftest-")
    ssh = make_fixture(tcd)

    rc, out, err = run(["scan", "--dir", ssh], fixture_dir=tcd)
    check("scan rc=0", rc == 0, f"rc={rc} err={err[:120]}")
    check("scan header", "keyvaultdog scan" in out)
    check("scan fingerprint column", "FINGERPRINT" in out)
    check("scan counts files", "(6 files)" in out, out[:200])

    rc, out, err = run(["scan", "--dir", ssh, "--json"], fixture_dir=tcd)
    check("I1 no key material in output", not leak_probe(ssh, out + err))

    rc, out, err = run(["audit", "--dir", ssh], fixture_dir=tcd)
    check("audit rc=1 (findings exist)", rc == 1, f"rc={rc}")
    for code in ("KV001", "KV002", "KV003", "KV004", "KV005"):
        check(f"audit finds {code}", code in out, out[:300])
    check("audit summary line", "summary:" in out and "HIGH" in out)

    rc, out, err = run(["audit", "--dir", ssh, "--json"], fixture_dir=tcd)
    try:
        doc = json.loads(out)
        ok = isinstance(doc.get("findings"), list) and len(doc["findings"]) >= 5
    except ValueError:
        ok = False
    check("audit --json parses", ok)

    clean = os.path.join(tcd, "cleanssh")
    os.makedirs(clean, mode=0o700)
    clean_key = os.path.join(clean, "id_ed25519")
    gen_key(clean_key, "ed25519_test_fixture_clean", passphrase="s3cretpw")
    rc, out, err = run(["audit", "--dir", clean], fixture_dir=tcd)
    check("clean fixture rc=0", rc == 0, out[:200])
    check("clean fixture no findings", "Kennel is clean" in out, out[:200])

    bfile = os.path.join(tcd, "baseline.json")
    rc, out, err = run(["baseline", "save", "--dir", ssh, "--file", bfile], fixture_dir=tcd)
    check("baseline save rc=0", rc == 0, f"rc={rc} {err[:120]}")
    check("baseline save counts", "fingerprints ->" in out)
    rc, out, err = run(["baseline", "show", "--file", bfile])
    check("baseline show rc=0", rc == 0, f"rc={rc} {err[:120]}")

    gen_key(os.path.join(ssh, "id_ed25519_new"), "ed25519_test_fixture_new")
    rc, out, err = run(["audit", "--dir", ssh, "--baseline", bfile], fixture_dir=tcd)
    check("audit --baseline finds KV010 NEW", "KV010" in out, out[:300])

    target = os.path.join(ssh, "id_ed25519")
    before = sorted(os.listdir(ssh))
    rc, out, err = run(["rotate", "--key", target], fixture_dir=tcd)
    check("rotate dry-run rc=0", rc == 0, f"rc={rc} {err[:120]}")
    check("rotate dry-run says dry-run", "dry-run" in out)
    check("I4 rotate dry-run writes nothing", before == sorted(os.listdir(ssh)))

    bdir = os.path.join(tcd, "backup")
    rc, out, err = run(["rotate", "--key", target, "--apply", "--backup-dir", bdir,
                        "--passphrase", "rotated-pw-2026"], fixture_dir=tcd)
    check("rotate apply rc=0", rc == 0, f"rc={rc} {err[:120]}")
    check("rotate apply creates dated key",
          any(n.startswith("id_ed25519.20") for n in os.listdir(ssh)))
    check("rotate apply backup exists", os.path.isdir(bdir) and len(os.listdir(bdir)) >= 1)
    with open(target, "r", errors="replace") as f:
        check("rotate apply old key untouched", "PRIVATE KEY" in f.read())
    new_key = [n for n in os.listdir(ssh) if n.startswith("id_ed25519.20")][0]
    rc2, out2, err2 = run(["audit", "--dir", ssh, "--max-age-days", "3650"], fixture_dir=tcd)
    check("rotate apply new key encrypted (audit ENC ok)",
          f"{new_key[:24]}" in out2 and re.search(new_key[:16] + r"\S*\s+PRIV\s+\S+\s+600\s+ok", out2) is not None,
          out2[:400])

    with open(os.path.join(ssh, "known_hosts"), "w") as f:
        f.write("secret-host-corp.internal ssh-ed25519 AAAAtest\n")
        f.write("203.0.113.7 ssh-ed25519 AAAAtest2\n")
    rc, out, err = run(["scan", "--dir", ssh], fixture_dir=tcd)
    check("I2 known_hosts hosts not printed",
          "secret-host-corp" not in out and "203.0.113.7" not in out and "known_hosts" in out)

    rc, out, err = run(["audit", "--dir", "/nonexistent-kvd"], fixture_dir=tcd)
    check("bad dir rc=2", rc == 2, f"rc={rc}")
    rc, out, err = run(["rotate", "--key", "/nonexistent-kvd/x"], fixture_dir=tcd)
    check("rotate missing key rc=2", rc == 2, f"rc={rc}")

    shutil.rmtree(tcd, ignore_errors=True)
    total = len(PASS) + len(FAIL)
    print()
    print(f"SELFTEST {'PASS' if not FAIL else 'FAIL'} {len(PASS)}/{total}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
