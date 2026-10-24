#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
keyvaultdog — SSH key assets hound, in one file, zero deps (stdlib only).

One command inventories every key asset in a key directory (~/.ssh by default),
audits it against a fixed invariant set, diffs against a baseline, and drafts a
rotation plan. Read-only by default; `rotate --apply` only ever ADDS new files.

  keyvaultdog scan   [--dir DIR] [--json]
  keyvaultdog audit  [--dir DIR] [--json] [--max-age-days N] [--baseline FILE]
  keyvaultdog baseline save|show [--dir DIR] [--file FILE]
  keyvaultdog rotate --key FILE [--apply] [--backup-dir DIR]

Exit codes: 0 = clean, 1 = findings, 2 = usage/runtime error (cron-friendly).

Invariants (the dog never breaks these):
  I1  never prints key material — fingerprints and filenames only
  I2  never prints known_hosts hostnames — entry counts and hashed-ratio only
  I3  scan/audit/baseline never write into the scanned directory
  I4  rotate dry-run writes nothing; rotate --apply only adds new files
  I5  paths are printed with $HOME abbreviated to ~
"""
import argparse
import datetime
import json
import os
import subprocess
import sys

VERSION = "1.1.0"
KEY_MARKERS = ("OPENSSH PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY")
PUB_MARKER = "PUBLIC KEY"
LINE = "-" * 74


def home_short(path):
    home = os.path.expanduser("~")
    if path.startswith(home + os.sep):
        return "~" + path[len(home):]
    return path


def eprint(*a):
    print(*a, file=sys.stderr)


# ---------------------------------------------------------------- ssh-keygen --
def ssh_keygen_available():
    try:
        subprocess.run(["ssh-keygen", "-h"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def fingerprint_of(path):
    """Returns (fpr_string, algo, bits) or (None, 'unknown', 0)."""
    try:
        r = subprocess.run(["ssh-keygen", "-lf", path], capture_output=True,
                           text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.strip().splitlines()[0].split()
            # "3072 SHA256:xxxx comment (RSA)"
            bits = int(parts[0]) if parts[0].isdigit() else 0
            fpr = parts[1] if len(parts) > 1 else None
            algo = "?"
            for p in parts:
                if p.startswith("(") and p.endswith(")"):
                    algo = p[1:-1]
            return fpr, algo, bits
    except (OSError, subprocess.SubprocessError):
        pass
    return None, "unknown", 0


def encrypted_state(path):
    """yes = passphrase protected; no = plaintext key (finding); unknown = ask a human."""
    try:
        r = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", path],
                           stdin=subprocess.DEVNULL, capture_output=True,
                           text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if r.returncode == 0:
        return "no"
    if "incorrect passphrase" in (r.stderr or "") or "invalid format" not in (r.stderr or ""):
        return "yes"
    return "unknown"


# ---------------------------------------------------------------- file model --
def classify(path):
    """-> (kind, algo, bits, fpr, encrypted)
    kind: priv / pub / config / known_hosts / other"""
    name = os.path.basename(path)
    try:
        head = open(path, "rb").read(4096).decode("utf-8", "replace")
    except OSError:
        return "unreadable", "unknown", 0, None, "unknown"

    if "OPENSSH PRIVATE KEY" in head or "PRIVATE KEY-----" in head:
        kind = "priv"
    elif PUB_MARKER in head or (name.endswith(".pub") and head.startswith(("ssh-", "ecdsa-", "sk-"))):
        kind = "pub"
    elif name == "known_hosts" or name.startswith("known_hosts."):
        kind = "known_hosts"
    elif name in ("config", "authorized_keys", "environment", "rc") or name.startswith("config."):
        kind = "config" if name == "config" else "other"
    else:
        kind = "other"

    fpr, algo, bits = (None, "-", 0)
    if kind in ("priv", "pub"):
        fpr, algo, bits = fingerprint_of(path)
    enc = encrypted_state(path) if kind == "priv" else "-"
    return kind, algo, bits, fpr, enc


def age_days(path, now=None):
    try:
        mt = os.path.getmtime(path)
    except OSError:
        return None
    now = now or datetime.datetime.now().timestamp()
    return int((now - mt) // 86400)


def perm_of(path):
    try:
        return oct(os.stat(path).st_mode & 0o777)[2:].zfill(3)
    except OSError:
        return "?"


def known_hosts_stats(path):
    """Counts only. I2: never returns or prints the hostnames themselves."""
    total, hashed, non_comment = 0, 0, 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                total += 1
                if ln.startswith("|1|"):
                    hashed += 1
                else:
                    non_comment += 1
    except OSError:
        pass
    return total, hashed, non_comment


def scan_dir(d):
    """Inventory. Returns (files_list, findings_pre) without mutating anything."""
    items = []
    for name in sorted(os.listdir(d)):
        if name.startswith(".keyvaultdog"):
            continue  # our own baseline
        p = os.path.join(d, name)
        if os.path.islink(p) or not os.path.isfile(p):
            continue
        kind, algo, bits, fpr, enc = classify(p)
        kh = None
        if kind == "known_hosts":
            total, hashed, plain = known_hosts_stats(p)
            kh = {"entries": total, "hashed": hashed, "plain": plain}
        items.append({
            "name": name, "path": p, "kind": kind, "algo": algo, "bits": bits,
            "fpr": fpr, "encrypted": enc, "perm": perm_of(p),
            "age_days": age_days(p), "size": os.path.getsize(p), "known_hosts": kh,
        })
    return items


# ---------------------------------------------------------------- findings ----
def audit(items, d, max_age_days, baseline_fprs=None):
    F = []  # (level, code, target, msg)

    try:
        dperm = oct(os.stat(d).st_mode & 0o777)[2:].zfill(3)
    except OSError:
        dperm = "?"
    if dperm != "?" and int(dperm, 8) & 0o077:
        F.append(("HIGH", "KV001", home_short(d),
                  f"key directory perm {dperm} is group/world reachable (want 700)"))

    privs = [i for i in items if i["kind"] == "priv"]
    pubs = [i for i in items if i["kind"] == "pub"]

    for it in privs:
        if it["perm"] != "?" and int(it["perm"], 8) & 0o077:
            F.append(("HIGH", "KV002", it["name"],
                      f"private key perm {it['perm']} (want 600) — any local user can read it"))
        if it["encrypted"] == "no":
            F.append(("HIGH", "KV003", it["name"],
                      "private key is NOT passphrase-encrypted — disk theft = key theft"))
        if it["age_days"] is not None and it["age_days"] > max_age_days:
            F.append(("MED", "KV004", it["name"],
                      f"key is {it['age_days']} days old (> {max_age_days}) — rotation overdue"))
        if it["fpr"] is None:
            F.append(("LOW", "KV012", it["name"], "unreadable/corrupt key — ssh-keygen cannot parse it"))

    priv_names = {os.path.splitext(i["name"])[0] for i in privs}
    for it in pubs:
        base = os.path.splitext(it["name"])[0]
        if base not in priv_names:
            F.append(("MED", "KV005", it["name"],
                      "zombie: public key with no matching private key — authorize-then-lose risk"))

    pairs = {}
    for it in privs + pubs:
        if it["fpr"]:
            pairs.setdefault((it["fpr"], it["kind"]), []).append(it["name"])
    for (fpr, kind), names in pairs.items():
        if len(names) > 1:
            F.append(("MED", "KV006", names[0],
                      f"same fingerprint across {len(names)} {kind} files: {', '.join(sorted(names))} — copies drift"))

    for it in items:
        if it["kind"] == "config" and it["perm"] != "?" and int(it["perm"], 8) & 0o044:
            F.append(("LOW", "KV007", it["name"],
                      f"ssh config perm {it['perm']} is group/world readable (want 600)"))
        if it["kind"] == "known_hosts" and it["known_hosts"] and it["known_hosts"]["plain"]:
            F.append(("LOW", "KV008", it["name"],
                      f"{it['known_hosts']['plain']} of {it['known_hosts']['entries']} known_hosts "
                      f"entries are plaintext hostnames (HashKnownHosts yes hashes them)"))

    if baseline_fprs is not None:
        now_fprs = {i["fpr"] for i in items if i.get("fpr")}
        for f in sorted(now_fprs - set(baseline_fprs)):
            F.append(("MED", "KV010", f,
                      "NEW key fingerprint appeared since baseline — expected?"))
        for f in sorted(set(baseline_fprs) - now_fprs):
            F.append(("MED", "KV011", f,
                      "baseline key fingerprint disappeared — removed on purpose?"))
    return F


LEVEL_ORDER = {"HIGH": 0, "MED": 1, "LOW": 2}


# ---------------------------------------------------------------- output ------
def print_table(items):
    hdr = f"{'FILE':28} {'KIND':12} {'ALGO':7} {'PERM':5} {'ENC':4} {'AGE(d)':7} FINGERPRINT"
    print(hdr)
    print(LINE)
    for i in items:
        kind = i["kind"].upper() if i["kind"] in ("priv", "pub") else i["kind"]
        enc = {"no": "NO!", "yes": "ok", "unknown": "?", "-": "-"}.get(str(i["encrypted"]), str(i["encrypted"]))
        age = str(i["age_days"]) if i["age_days"] is not None else "?"
        fpr = i["fpr"] or "-"
        print(f"{i['name'][:27]:28} {kind:12} {i['algo'][:6]:7} {i['perm']:5} {enc:4} {age:7} {fpr}")


def print_findings(F):
    if not F:
        print("No findings. Kennel is clean.")
        return
    for lvl, code, tgt, msg in sorted(F, key=lambda x: (LEVEL_ORDER[x[0]], x[1], x[2])):
        print(f"[{lvl}] {code} {tgt}: {msg}")


def summary(F):
    c = {"HIGH": 0, "MED": 0, "LOW": 0}
    for lvl, *_ in F:
        c[lvl] += 1
    return f"summary: {len(F)} findings — HIGH {c['HIGH']} / MED {c['MED']} / LOW {c['LOW']}"


def load_baseline(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return set(json.load(f).get("fingerprints", []))
    except (OSError, ValueError):
        return None


def save_baseline(items, path):
    fprs = sorted({i["fpr"] for i in items if i.get("fpr")})
    doc = {"version": VERSION,
           "saved_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
           "fingerprints": fprs}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    return len(fprs)


# ---------------------------------------------------------------- rotate ------
def rotate(key_path, apply_mode, backup_dir=None, passphrase=""):
    key_path = os.path.abspath(key_path)
    if not os.path.isfile(key_path):
        eprint(f"rotate: no such file: {key_path}")
        return 2
    kind, algo, bits, fpr, enc = classify(key_path)
    if kind != "priv":
        eprint("rotate: not a private key file")
        return 2
    d = os.path.dirname(key_path)
    base = os.path.splitext(os.path.basename(key_path))[0]
    stamp = datetime.date.today().strftime("%Y%m%d")
    new_key = os.path.join(d, f"{base}.{stamp}")
    new_pub = new_key + ".pub"

    plan = [
        f"rotate plan for {home_short(key_path)}",
        f"  current : {algo} {bits}bit  {fpr}  encrypted={enc}",
        f"  new     : ed25519 -> {home_short(new_key)} (+ .pub), passphrase={'set' if passphrase else 'EMPTY (will re-trip KV003)'}, old key is NOT deleted",
        "  then    : 1) append new .pub to authorized_keys on every host that trusts the old key",
        "            2) verify ssh -i <new key> <host> true",
        "            3) only then remove the old public key line and archive the old private key",
    ]
    for ln in plan:
        print(ln)
    if not apply_mode:
        print("dry-run: nothing written (pass --apply to generate the new keypair)")
        return 0

    if os.path.exists(new_key) or os.path.exists(new_pub):
        eprint(f"rotate: {new_key} already exists — refuse to overwrite")
        return 2
    if backup_dir:
        os.makedirs(backup_dir, exist_ok=True)
        for src in (key_path, key_path + ".pub"):
            if os.path.isfile(src):
                dst = os.path.join(backup_dir, os.path.basename(src))
                with open(src, "rb") as a, open(dst, "wb") as b:
                    b.write(a.read())
                os.chmod(dst, 0o600)
        print(f"backup: copied originals to {home_short(backup_dir)} (perm 600)")
    try:
        r = subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", passphrase, "-C",
                            f"rotated-{stamp}", "-f", new_key, "-q"],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        eprint(f"rotate: ssh-keygen failed: {e}")
        return 2
    if r.returncode != 0:
        eprint(f"rotate: ssh-keygen failed: {(r.stderr or '').strip()[:200]}")
        return 2
    os.chmod(new_key, 0o600)
    nf, na, nb = fingerprint_of(new_key)
    print(f"applied: generated {home_short(new_key)} ed25519 {nb}bit {nf}")
    print("reminders: old key left untouched; complete the 3-step cutover before deleting it")
    return 0


# ---------------------------------------------------------------- main --------
def main(argv=None):
    ap = argparse.ArgumentParser(prog="keyvaultdog",
                                 description="SSH key assets hound — inventory, audit, baseline, rotate")
    ap.add_argument("--version", action="version", version=f"keyvaultdog {VERSION}")
    sub = ap.add_subparsers(dest="cmd")

    def add_common(sp):
        sp.add_argument("--dir", default=os.path.expanduser("~/.ssh"))
        sp.add_argument("--json", action="store_true")

    p_scan = sub.add_parser("scan", help="inventory every key asset")
    add_common(p_scan)

    p_audit = sub.add_parser("audit", help="inventory + invariant findings")
    add_common(p_audit)
    p_audit.add_argument("--max-age-days", type=int, default=365)
    p_audit.add_argument("--baseline")

    p_base = sub.add_parser("baseline", help="save/show fingerprint baseline")
    add_common(p_base)
    p_base.add_argument("action", choices=["save", "show"])
    p_base.add_argument("--file", default=os.path.expanduser("~/.keyvaultdog-baseline.json"))

    p_rot = sub.add_parser("rotate", help="draft (or run) a key rotation")
    p_rot.add_argument("--key", required=True)
    p_rot.add_argument("--apply", action="store_true")
    p_rot.add_argument("--passphrase", default="",
                       help="passphrase for the NEW key (empty = naked key, will re-trip KV003)")
    p_rot.add_argument("--backup-dir", default=None)

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 2
    if args.cmd != "rotate" and not os.path.isdir(args.dir):
        eprint(f"keyvaultdog: directory not found: {args.dir}")
        return 2

    if args.cmd == "rotate":
        return rotate(args.key, args.apply, args.backup_dir, getattr(args, "passphrase", ""))

    items = scan_dir(args.dir)

    if args.cmd == "scan":
        if args.json:
            print(json.dumps({"tool": "keyvaultdog", "version": VERSION, "dir": home_short(args.dir),
                              "files": [{k: v for k, v in i.items() if k != "path"} for i in items]},
                             ensure_ascii=False, indent=2))
        else:
            print(f"keyvaultdog scan — {home_short(args.dir)} ({len(items)} files)")
            print_table(items)
            print(summary(audit(items, args.dir, 10 ** 9)))
        return 0

    baseline_fprs = None
    if args.cmd == "audit" and args.baseline:
        baseline_fprs = load_baseline(args.baseline)
        if baseline_fprs is None:
            eprint(f"keyvaultdog: cannot read baseline: {args.baseline}")
            return 2

    F = audit(items, args.dir,
              args.max_age_days if args.cmd == "audit" else 10 ** 9, baseline_fprs)
    if args.cmd == "baseline":
        if args.action == "show":
            path = args.file
            b = load_baseline(path)
            if b is None:
                eprint("no baseline (run: keyvaultdog baseline save)")
                return 2
            print(f"baseline {home_short(path)}: {len(b)} fingerprints")
            return 0
        path = args.file
        n = save_baseline(items, path)
        print(f"baseline saved: {n} fingerprints -> {home_short(path)}")
        return 0

    if args.json:
        print(json.dumps({"tool": "keyvaultdog", "version": VERSION, "dir": home_short(args.dir),
                          "findings": [{"level": l, "code": c, "target": t, "msg": m}
                                       for l, c, t, m in F]},
                         ensure_ascii=False, indent=2))
    else:
        print(f"keyvaultdog audit — {home_short(args.dir)} ({len(items)} files)")
        print_table(items)
        print(LINE)
        print_findings(F)
        print(summary(F))
    return 1 if F else 0


if __name__ == "__main__":
    sys.exit(main())
