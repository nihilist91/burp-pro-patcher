#!/usr/bin/env python3
# re_burp/patch_code.py
"""Replace method bodies with explicit bytecode.

Targets are NAME(DESCRIPTOR) or bare NAME, optionally repeated. max_locals is
preserved from the original Code attribute.

    py patch_code.py --input . --target 'burp/Zo8#ZI(Ljava/lang/String;Lburp/Zl52;)' \
        --code bb017959b7018fb0 --stack 2 --dry-run
    py patch_code.py --input . --target 'burp/Zo8#ZI(Ljava/lang/String;Lburp/Zl52;)' \
        --code bb017959b7018fb0 --stack 2 --apply

Dependencies: Python >= 3.9 standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import sys
import tempfile
import time
import zipfile
from typing import Dict, List, Sequence, Tuple

import patch_burp as P


def pick(cf: P.ClassFile, spec: str) -> P.Method:
    if "(" in spec:
        name, desc = spec.split("(", 1)
        desc = "(" + desc
    else:
        name, desc = spec, None
    hits = []
    for m in cf.methods:
        if (cf.utf8_text(m.name_index) or "") != name:
            continue
        if desc is not None and not (cf.utf8_text(m.desc_index) or "").startswith(desc):
            continue
        if m.access & (0x0100 | 0x0400):
            continue
        if not any(cf.utf8_text(a.name_index) == "Code" for a in m.attributes):
            continue
        hits.append(m)
    if len(hits) != 1:
        raise P.PatchError("%d methods match %s, need exactly 1" % (len(hits), spec))
    return hits[0]


def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(prog="patch_code.py")
    ap.add_argument("--input", required=True)
    ap.add_argument("--target", default=[], action="append", metavar="CLASS#METHOD")
    ap.add_argument("--code", metavar="HEX")
    ap.add_argument("--stack", type=int, default=2)
    ap.add_argument("--expect")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)

    try:
        jar = P.resolve_input(a.input)
        if a.restore:
            return P.do_restore(jar)
        if a.verify:
            return P.do_verify(jar)

        code = bytes.fromhex("".join(a.code.split()))
        cur = P.sha256_file(jar)
        if a.expect and cur != a.expect.lower() and not a.force:
            raise P.PatchError("hash gate: expected %s, found %s" % (a.expect.lower(), cur))

        plans: List[Tuple[str, str]] = []
        for spec in a.target:
            if "#" not in spec:
                raise P.PatchError("target %r needs CLASS#METHOD" % spec)
            cls, meth = spec.split("#", 1)
            if not cls.endswith(".class"):
                cls += ".class"
            plans.append((cls, meth))

        edits: List[P.Edit] = []
        out: Dict[str, bytes] = {}
        with zipfile.ZipFile(jar) as zf:
            names = zf.namelist()
            for cls, meth in plans:
                if cls not in names:
                    raise P.PatchError("no such entry: %s" % cls)
                blob = zf.read(cls)
                cf = P.ClassFile(blob)
                m = pick(cf, meth)
                attr = next(x for x in m.attributes if cf.utf8_text(x.name_index) == "Code")
                old = blob[attr.start:attr.end]
                max_locals = struct.unpack_from(">H", old, 8)[0]
                desc = cf.utf8_text(m.desc_index) or "?"
                new = (struct.pack(">H", attr.name_index) + struct.pack(">I", len(code) + 12)
                       + struct.pack(">H", a.stack) + struct.pack(">H", max_locals)
                       + struct.pack(">I", len(code)) + code
                       + struct.pack(">H", 0) + struct.pack(">H", 0))
                rec = {"kind": "body_force_true", "class": cls,
                       "method": meth.split("(")[0], "descriptor": desc}
                edits.append(P.Edit(cls, attr.start, old, new,
                                    "%s%s -> %s" % (meth, desc, code.hex()), rec))

            for cls in {e.class_name for e in edits}:
                class_edits = [e for e in edits if e.class_name == cls]
                blob, offs = P.splice(zf.read(cls), class_edits)
                for e in class_edits:
                    e.record["attr_offset_post"] = offs[e.key]
                out[cls] = blob

        for e in edits:
            print("%s 0x%08x  %s -> %s  (%s)" %
                  (e.class_name, e.offset, P.preview(e.old), P.preview(e.new), e.reason))
        if not a.apply:
            print("DRY RUN: %d edit(s), jar untouched" % len(edits))
            print("OK: dry run complete")
            return 0

        bak = P.backup_path(jar)
        if not os.path.isfile(bak):
            shutil.copy2(jar, bak)
        drop = set(P.signature_entries(jar))
        fd, tmp = tempfile.mkstemp(suffix=".jar", dir=os.path.dirname(jar) or ".")
        os.close(fd)
        try:
            P.rebuild_jar(jar, tmp, out, drop)
            os.replace(tmp, jar)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

        post = P.sha256_file(jar)
        with open(P.sidecar_path(jar), "w", encoding="utf-8") as fh:
            json.dump({"schema": P.SCHEMA, "jar": os.path.basename(jar),
                       "mode": "code", "pre_sha256": cur, "post_sha256": post,
                       "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "edits": [e.record for e in edits], "stripped": sorted(drop)},
                      fh, indent=2)
            fh.write("\n")
        print("sha256 %s -> %s" % (cur, post))
        print("OK: patched %d method(s)" % len(edits))
        return 0
    except P.PatchError as exc:
        print("FAIL: %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))