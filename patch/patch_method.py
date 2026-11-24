#!/usr/bin/env python3
# re_burp/patch_method.py
"""Force named boolean methods to `return true` by rewriting their Code attribute.

Same edit engine, sidecar format and safety rails as patch_burp.py, but with
explicit targeting instead of scoring -- for obfuscated classes the heuristics
cannot reach.

    py patch_method.py --input . --target burp/Zhxf#verify --list
    py patch_method.py --input . --target burp/Zhxf#verify --dry-run
    py patch_method.py --input . --target burp/Zhxf#verify --expect <sha> --apply

Target syntax: CLASS#METHOD, or CLASS#*Z for every )Z method in CLASS.
Success prints "OK: ..." and exits 0. Failure prints "FAIL: ..." and exits 1.
Dependencies: Python >= 3.9 standard library only.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import tempfile
import time
import zipfile
from typing import Dict, List, Sequence, Tuple

import patch_burp as P

ACC_STATIC = 0x0008
ACC_NATIVE = 0x0100
ACC_ABSTRACT = 0x0400


def targets_of(blob: bytes) -> Tuple[P.ClassFile, List[P.Method]]:
    cf = P.ClassFile(blob)
    return cf, cf.methods


def select(cf: P.ClassFile, want: str) -> List[P.Method]:
    out: List[P.Method] = []
    for method in cf.methods:
        name = cf.utf8_text(method.name_index) or ""
        desc = cf.utf8_text(method.desc_index) or ""
        if method.access & (ACC_ABSTRACT | ACC_NATIVE):
            continue
        if not any(a for a in method.attributes
                   if cf.utf8_text(a.name_index) == "Code"):
            continue
        if want == "*Z":
            if desc.endswith(")Z"):
                out.append(method)
        elif name == want:
            out.append(method)
    return out


def build_edit(cf: P.ClassFile, data: bytes, entry: str, method: P.Method) -> P.Edit:
    attr = next(a for a in method.attributes if cf.utf8_text(a.name_index) == "Code")
    old = data[attr.start:attr.end]
    max_locals = struct.unpack_from(">H", old, 8)[0]
    name = cf.utf8_text(method.name_index) or "?"
    desc = cf.utf8_text(method.desc_index) or "?"
    if desc.endswith(")V"):
        code, stack = b"\xb1", 0          # return
    else:
        code, stack = b"\x04\xac", 1      # iconst_1 ; ireturn
    new = (struct.pack(">H", attr.name_index) + struct.pack(">I", 14)
           + struct.pack(">H", stack) + struct.pack(">H", max_locals)
           + struct.pack(">I", len(code)) + code
           + struct.pack(">H", 0) + struct.pack(">H", 0))
    return P.Edit(entry, attr.start, old, new,
                  "%s%s -> %s" % (name, desc, "return" if stack == 0 else "iconst_1; ireturn"),
                  {"kind": "body_force_true", "method": name, "descriptor": desc})


def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(prog="patch_method.py")
    ap.add_argument("--input", required=True, metavar="PATH")
    ap.add_argument("--target", required=True, action="append", metavar="CLASS#METHOD",
                    help="CLASS#METHOD or CLASS#*Z; repeatable")
    ap.add_argument("--expect", metavar="SHA256")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    try:
        jar = P.resolve_input(args.input)
        if args.restore:
            return P.do_restore(jar)
        if args.verify:
            return P.do_verify(jar)

        plans: List[Tuple[str, str]] = []
        for spec in args.target:
            if "#" not in spec:
                raise P.PatchError("target %r needs CLASS#METHOD" % spec)
            cls, meth = spec.split("#", 1)
            if not cls.endswith(".class"):
                cls += ".class"
            plans.append((cls, meth))

        with zipfile.ZipFile(jar) as zf:
            names = set(zf.namelist())
            for cls, meth in plans:
                if cls not in names:
                    raise P.PatchError("no such entry: %s" % cls)

        if args.list:
            with zipfile.ZipFile(jar) as zf:
                for cls, meth in plans:
                    cf, methods = targets_of(zf.read(cls))
                    print("%s  (%d methods)" % (cls, len(methods)))
                    for m in methods:
                        name = cf.utf8_text(m.name_index) or "?"
                        desc = cf.utf8_text(m.desc_index) or "?"
                        mark = ""
                        if meth == "*Z" and desc.endswith(")Z"):
                            mark = "  <== selected"
                        elif name == meth:
                            mark = "  <== selected"
                        print("  0x%04x  %s%s%s" % (m.access, name, desc, mark))
            print("OK: listing complete, jar untouched")
            return 0

        current = P.sha256_file(jar)
        side = P.sidecar_path(jar)
        if os.path.isfile(side) and not args.force:
            with open(side, encoding="utf-8") as fh:
                import json
                prior = json.load(fh)
            if prior.get("post_sha256") == current:
                print("OK: already patched (sidecar matches), nothing to do")
                return 0
            raise P.PatchError("jar changed since last patch; rerun with --force")
        if args.expect and current != args.expect.lower():
            if not args.force:
                raise P.PatchError("hash gate: expected %s, found %s"
                                   % (args.expect.lower(), current))
            print("warning: hash gate overridden")

        edits: List[P.Edit] = []
        new_blobs: Dict[str, bytes] = {}
        with zipfile.ZipFile(jar) as zf:
            for cls, meth in plans:
                cf, _ = targets_of(zf.read(cls))
                picked = select(cf, meth)
                if not picked:
                    raise P.PatchError("no matching method for %s#%s" % (cls, meth))
                class_edits = [build_edit(cf, zf.read(cls), cls, m) for m in picked]
                blob, offsets = P.splice(zf.read(cls), class_edits)
                for edit in class_edits:
                    edit.record["class"] = cls
                    edit.record["attr_offset_post"] = offsets[edit.key]
                edits.extend(class_edits)
                new_blobs[cls] = blob

        for edit in edits:
            print("%s 0x%08x  %s -> %s  (%s)"
                  % (edit.class_name, edit.offset, P.preview(edit.old),
                     P.preview(edit.new), edit.reason))

        if not args.apply:
            print("DRY RUN: %d edit(s) across %d class(es)" % (len(edits), len(new_blobs)))
            print("OK: dry run complete, jar untouched")
            return 0

        bak = P.backup_path(jar)
        if not os.path.isfile(bak):
            import shutil
            shutil.copy2(jar, bak)
            print("backup   %s" % bak)

        drop = set(P.signature_entries(jar))
        fd, tmp = tempfile.mkstemp(suffix=".jar", dir=os.path.dirname(jar) or ".")
        os.close(fd)
        try:
            P.rebuild_jar(jar, tmp, new_blobs, drop)
            os.replace(tmp, jar)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

        post = P.sha256_file(jar)
        with open(side, "w", encoding="utf-8") as fh:
            import json
            json.dump({"schema": P.SCHEMA, "jar": os.path.basename(jar),
                       "mode": "targeted", "pre_sha256": current, "post_sha256": post,
                       "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "edits": [e.record for e in edits], "stripped": sorted(drop)},
                      fh, indent=2)
            fh.write("\n")
        print("sha256   %s -> %s" % (current, post))
        print("OK: forced %d method(s), %d entry drop(s)" % (len(edits), len(drop)))
        return 0
    except P.PatchError as exc:
        print("FAIL: %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))