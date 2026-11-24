#!/usr/bin/env python3
# re_burp/patch_licence.py
"""Make burp.Zu6.ZG(String,int) return a synthetic licence Object[] so the whole
codec chain is bypassed and Zug1.Zx builds a real Zudh from it.

Appends constant-pool entries, then writes the body. Dependencies: stdlib only.
"""
import argparse, json, os, shutil, struct, sys, tempfile, time, zipfile
import patch_burp as P

TARGET = "burp/Zu6.class"
METHOD = "ZG"
DESC = "(Ljava/lang/String;I)[Ljava/lang/Object;"


def cp_end(d):
    n = struct.unpack_from(">H", d, 8)[0]
    off, i = 10, 1
    while i < n:
        t = d[off]; off += 1
        if t == 1:
            off += 2 + struct.unpack_from(">H", d, off)[0]
        elif t in (5, 6):
            off += 8; i += 2; continue
        elif t in (3, 4, 9, 10, 11, 12, 17, 18): off += 4
        elif t in (7, 8, 16, 19, 20): off += 2
        elif t == 15: off += 3
        else: raise P.PatchError("bad cp tag %d" % t)
        i += 1
    return off, n


def main(argv):
    ap = argparse.ArgumentParser(prog="patch_licence.py")
    ap.add_argument("--input", required=True)
    ap.add_argument("--caption", default="licensed to nihilist")
    ap.add_argument("--key", default="6f1d2a4c-0b7e-4c31-9a58-1e2b3c4d5e6f")
    ap.add_argument("--days", type=int, default=3650)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    try:
        jar = P.resolve_input(a.input)
        if a.restore: return P.do_restore(jar)
        if a.verify: return P.do_verify(jar)

        d = zipfile.ZipFile(jar).read(TARGET)
        end, count = cp_end(d)
        nxt = count
        add = bytearray()

        def utf8(s):
            b = s.encode("utf-8"); return b"\x01" + struct.pack(">H", len(b)) + b

        def add_utf8(s):
            nonlocal nxt
            idx = nxt; nxt += 1; add.extend(utf8(s)); return idx

        def add_str(s):
            nonlocal nxt
            u = add_utf8(s); idx = nxt; nxt += 1
            add.extend(b"\x08" + struct.pack(">H", u)); return idx

        s1 = add_str(a.caption)
        s2 = add_str(a.key)
        long_idx = nxt; nxt += 2
        add.extend(b"\x05" + struct.pack(">q", int((time.time() + a.days*86400)*1000)))
        cu = add_utf8("java/lang/Long")
        long_cls = nxt; nxt += 1
        add.extend(b"\x07" + struct.pack(">H", cu))
        nu = add_utf8("valueOf")
        du = add_utf8("(J)Ljava/lang/Long;")
        nat = nxt; nxt += 1
        add.extend(b"\x0c" + struct.pack(">HH", nu, du))
        vof = nxt; nxt += 1
        add.extend(b"\x0a" + struct.pack(">HH", long_cls, nat))

        obj_cls = 0x1f          # #31 = Class java/lang/Object
        int_vof = 0x31          # #49 = Integer.valueOf

        code = bytearray()
        code += b"\x10\x04"                          # bipush 4
        code += b"\xbd" + struct.pack(">H", obj_cls) # anewarray Object
        code += b"\x59\x03\x12" + bytes([s1]) + b"\x53"
        code += b"\x59\x04\x12" + bytes([s2]) + b"\x53"
        code += b"\x59\x05\x14" + struct.pack(">H", long_idx)
        code += b"\xb8" + struct.pack(">H", vof) + b"\x53"
        code += b"\x59\x06\x04"
        code += b"\xb8" + struct.pack(">H", int_vof) + b"\x53"
        code += b"\xb0"

        cf = P.ClassFile(d)
        m = [x for x in cf.methods if (cf.utf8_text(x.name_index) or "") == METHOD
             and (cf.utf8_text(x.desc_index) or "") == DESC][0]
        at = [x for x in m.attributes if cf.utf8_text(x.name_index) == "Code"][0]
        max_locals = struct.unpack_from(">H", d, at.body_off + 2)[0]
        body = (struct.pack(">H", at.name_index) + struct.pack(">I", len(code) + 12)
                + struct.pack(">H", 6) + struct.pack(">H", max_locals)
                + struct.pack(">I", len(code)) + bytes(code)
                + struct.pack(">H", 0) + struct.pack(">H", 0))

        edits = [
            P.Edit(TARGET, 8, d[8:10], struct.pack(">H", nxt), {}, ""),
            P.Edit(TARGET, end, b"", bytes(add), {}, ""),
            P.Edit(TARGET, at.start, d[at.start:at.end], body, {}, ""),
        ]
        out, _ = P.splice(d, edits)
        print("cp_count %d -> %d, body %d bytes, max_locals=%d" % (count, nxt, len(code), max_locals))
        if not a.apply:
            print("DRY RUN: jar untouched"); return 0
        bak = P.backup_path(jar)
        if not os.path.isfile(bak): shutil.copy2(jar, bak)
        drop = set(P.signature_entries(jar))
        fd, tmp = tempfile.mkstemp(suffix=".jar", dir=os.path.dirname(jar) or "."); os.close(fd)
        P.rebuild_jar(jar, tmp, {TARGET: out}, drop); os.replace(tmp, jar)
        post = P.sha256_file(jar)
        with open(P.sidecar_path(jar), "w", encoding="utf-8") as fh:
            json.dump({"schema": P.SCHEMA, "jar": os.path.basename(jar), "mode": "licence",
                       "pre_sha256": P.sha256_file(bak), "post_sha256": post,
                       "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "edits": [{"kind": "utf8_keyswap", "class": TARGET,
                                  "encoding": "licence_body", "offset_post": 8,
                                  "new_text": "Object[4]"}],
                       "stripped": sorted(drop)}, fh, indent=2); fh.write("\n")
        print("OK: patched, sha256 %s" % post); return 0
    except P.PatchError as e:
        print("FAIL: %s" % e); return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))