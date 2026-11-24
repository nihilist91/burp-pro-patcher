#!/usr/bin/env python3
# re_burp/verify_burp.py - exit 0 only when all four patches are present and the
# codec actually returns a licence array. Stdlib only.
import argparse, os, struct, subprocess, sys, zipfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'patch'))
import patch_burp as P

BODIES = [
    ("burp/Zhxf.class", "Zr", "(Ljava/lang/String;)Z", b"\x04\xac"),
    ("burp/Zn15.class", "Zl", "(Lburp/Zhzs;Ljava/lang/String;)Z", b"\x04\xac"),
    ("burp/Ztk8.class", "Ze", "(Ljava/lang/String;)V", b"\xb1"),
]
ZG = ("burp/Zu6.class", "ZG", "(Ljava/lang/String;I)[Ljava/lang/Object;")


def code_of(blob, cf, name, desc):
    """Return (code_bytes, code_length_field_ok) for the first matching method."""
    for m in cf.methods:
        if (cf.utf8_text(m.name_index) or "") != name:
            continue
        if desc and (cf.utf8_text(m.desc_index) or "") != desc:
            continue
        for a in m.attributes:
            if cf.utf8_text(a.name_index) != "Code":
                continue
            body = blob[a.body_off:a.body_off + a.length]
            if len(body) < 12:
                return None, False
            code_len = struct.unpack_from(">I", body, 4)[0]
            ok = code_len == len(body) - 12
            return body[8:8 + code_len], ok
    return None, False


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
        names = zf.namelist()
        for entry, name, desc, want in BODIES:
            if entry not in names:
                print("  [FAIL] %s missing" % entry); bad += 1; continue
            cf = P.ClassFile(zf.read(entry))
            code, len_ok = code_of(zf.read(entry), cf, name, desc)
            ok = code is not None and code == want and len_ok
            print("  [%s] %s.%s body" % (" ok " if ok else "FAIL", entry, name))
            bad += 0 if ok else 1

        entry, name, desc = ZG
        if entry not in names:
            print("  [FAIL] %s missing" % entry); bad += 1
        else:
            blob = zf.read(entry)
            cf = P.ClassFile(blob)
            code, len_ok = code_of(blob, cf, name, desc)
            ok = (code is not None and len_ok and code[:3] == b"\x10\x04\xbd"
                  and code[-1:] == b"\xb0" and len(code) == 32)
            print("  [%s] %s.%s returns Object[4]" % (" ok " if ok else "FAIL", entry, name))
            bad += 0 if ok else 1

    vdir = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isfile(os.path.join(vdir, "Dec.class")):
        subprocess.run(["javac", "-cp", os.path.basename(jar), "-d", vdir,
                        os.path.join(vdir, "Dec.java")], cwd=os.path.dirname(jar),
                       check=False)
    try:
        r = subprocess.run(["java", "-cp", ".;verify;" + os.path.basename(jar), "Dec", "x", "1"],
                           cwd=os.path.dirname(jar), capture_output=True, text=True, timeout=180)
        ok = "out0: " in r.stdout and "licensed to" in r.stdout
        print("  [%s] codec returns a licence" % (" ok " if ok else "FAIL"))
        if not ok:
            print("    " + (r.stdout + r.stderr).strip().replace("\n", "\n    "))
            bad += 1
    except (OSError, subprocess.SubprocessError) as exc:
        print("  [FAIL] java check: %s" % exc); bad += 1

    print("OK: authorized" if not bad else "FAIL: %d check(s) failed" % bad)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
