#!/usr/bin/env python3
# re_burp/verify_burp.py — exit 0 only when all four patches are present and the
# codec actually returns a licence array. Stdlib only.
import argparse, os, struct, subprocess, sys, zipfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'patch'))
import patch_burp as P

EXPECT = {"burp/Zhxf.class": b"\x04\xac", "burp/Zn15.class": b"\x04\xac",
          "burp/Ztk8.class": b"\xb1"}

def body_of(blob, cf, name, desc):
    for m in cf.methods:
        if (cf.utf8_text(m.name_index) or "") != name:
            continue
        if desc and (cf.utf8_text(m.desc_index) or "") != desc:
            continue
        for a in m.attributes:
            if cf.utf8_text(a.name_index) == "Code":
                return blob[a.body_off:a.body_off + a.length]
    return None

def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--verify", action="store_true")
    a = ap.parse_args(argv)
    jar = os.path.abspath(a.input)
    bad = 0

    with zipfile.ZipFile(jar) as zf:
        for entry, want in EXPECT.items():
            if entry not in zf.namelist():
                print("  [FAIL] %s missing" % entry); bad += 1; continue
            blob = zf.read(entry); cf = P.ClassFile(blob)
            name = {b"\x04\xac": None, b"\xb1": "Ze"}[want]
            desc = {None: None, "Ze": "(Ljava/lang/String;)V"}[name]
            b = body_of(blob, cf, name or "Zr", desc)
            if b is None:
                b = body_of(blob, cf, "Zl", "(Lburp/Zhzs;Ljava/lang/String;)Z")
            ok = b is not None and b[8:8 + len(want)] == want and struct.unpack_from(">I", b, 4)[0] == len(b) - 8
            print("  [%s] %s body" % (" ok " if ok else "FAIL", entry))
            bad += 0 if ok else 1

        blob = zf.read("burp/Zu6.class"); cf = P.ClassFile(blob)
        b = body_of(blob, cf, "ZG", "(Ljava/lang/String;I)[Ljava/lang/Object;")
        ok = b is not None and b[8:11] == b"\x10\x04\xbd" and b[8 + 0x1a:8 + 0x1b] == b"\xb0"
        print("  [%s] burp/Zu6.ZG returns Object[4]" % (" ok " if ok else "FAIL"))
        bad += 0 if ok else 1

    try:
        r = subprocess.run(["java", "-cp", ".;" + os.path.basename(jar), "Dec", "x", "1"],
                           cwd=os.path.dirname(jar), capture_output=True, text=True, timeout=120)
        out = r.stdout
        ok = "out0: " in out and "licensed to" in out
        print("  [%s] codec returns a licence (java Dec)" % (" ok " if ok else "FAIL"))
        if not ok:
            print("    " + out.strip().replace("\n", "\n    ")); bad += 1
    except (OSError, subprocess.SubprocessError) as exc:
        print("  [FAIL] java check: %s" % exc); bad += 1

    print("OK: authorized" if not bad else "FAIL: %d check(s) failed" % bad)
    return 0 if not bad else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))