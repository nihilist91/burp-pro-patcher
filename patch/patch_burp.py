#!/usr/bin/env python3
# re_burp/patch_burp.py
"""Neutralise the Burp Suite Professional licence gate by swapping the RSA trust
anchor embedded in its class constants, or (fallback, mode=body) by forcing the
licence-check predicates to return true.

Run — diagnose only, touches nothing:
    python3 patch_burp.py --input burpsuite_pro_v2023.6.jar --list

Run — apply a key swap, hash gated, dry run first:
    python3 patch_burp.py --input burpsuite_pro_v2023.6.jar --expect <sha256> \
        --pubkey <SPKI-BASE64> --dry-run
    python3 patch_burp.py --input burpsuite_pro_v2023.6.jar --expect <sha256> \
        --pubkey <SPKI-BASE64> --apply

Run — re-check the recorded edits (exit 0 == authorized):
    python3 patch_burp.py --input burpsuite_pro_v2023.6.jar --verify

Run — byte-exact restore from <file>.orig:
    python3 patch_burp.py --input burpsuite_pro_v2023.6.jar --restore

Success looks like a line beginning "OK:" and exit status 0. Any failure prints
"FAIL: <reason>" and exits 1.

Dependencies: Python >= 3.9 standard library only. The `openssl` binary is used
only when --privkey is given, to derive the public half and modulus:
    Debian/Ubuntu:  sudo apt install openssl
    macOS:          brew install openssl
    Windows:        winget install ShiningLight.OpenSSL.Light

Technique ladder position: byte patch (tier 1). The class file is edited in
place with a real constant-pool parser, so the jar keeps its entry order,
alignment and compression. No decompile-and-recompile is required.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from typing import Dict, List, Optional, Sequence, Set, Tuple

SCHEMA = 1

# A raw RSA modulus is 128/256/384/512 bytes for 1024/2048/3072/4096 bit keys.
KEY_DECODED_LENGTHS = (128, 256, 384, 512)

DIGEST_PROBES = (
    b"SHA256withRSA",
    b"SHA1withRSA",
    b"MD5withRSA",
    b"sha256WithRSAEncryption",
    b"sha1WithRSAEncryption",
    b"md5WithRSAEncryption",
    b"SHA-256",
    b"SHA-1",
    b"MD5",
)

SIG_ENTRY_RE = re.compile(r"^META-INF/[^/]+\.(SF|RSA|DSA|EC)$", re.IGNORECASE)
EXTRA_STRIP = ("META-INF/INDEX.LIST",)

PRO_NAME_RE = re.compile(
    r"^(is)?(pro|pro_?version|pro_?edition|licensed|valid_?license"
    r"|license_?valid|has_?license|isvalid)$",
    re.IGNORECASE,
)

MAIN_CLASS = "burp/StartBurp.class"

# Constant-pool tag -> payload size, where the size is the fixed part only.
CP_FIXED = {
    3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4,
    15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2,
}
CP_TWO_SLOT = (5, 6)

BODY_SCORE_THRESHOLD = 8
BODY_MAX_CLASSES = 4


class PatchError(Exception):
    """Any recoverable failure; main() turns it into FAIL: + exit 1."""


def fail(msg: str) -> "None":
    print("FAIL: " + msg)
    raise SystemExit(1)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def u2(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        raise PatchError("truncated class file at 0x%x (u2)" % off)
    return struct.unpack_from(">H", data, off)[0]


def u4(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        raise PatchError("truncated class file at 0x%x (u4)" % off)
    return struct.unpack_from(">I", data, off)[0]


def preview(blob: bytes, limit: int = 24) -> str:
    try:
        text = blob.decode("ascii")
    except UnicodeDecodeError:
        text = blob.hex()
        limit = min(limit, 24)
    if len(text) <= limit:
        return text
    return text[:limit] + "..[%d]" % len(blob)


def sidecar_path(jar: str) -> str:
    return jar + ".patchstate.json"


def backup_path(jar: str) -> str:
    return jar + ".orig"


# --------------------------------------------------------------------------- #
# class file parsing
# --------------------------------------------------------------------------- #

class Utf8Entry:
    __slots__ = ("index", "len_off", "value_off", "value")

    def __init__(self, index: int, len_off: int, value_off: int, value: bytes) -> None:
        self.index = index
        self.len_off = len_off
        self.value_off = value_off
        self.value = value


class Attribute:
    __slots__ = ("name_index", "start", "len_off", "body_off", "length")

    def __init__(self, name_index: int, start: int, len_off: int, body_off: int,
                 length: int) -> None:
        self.name_index = name_index
        self.start = start          # offset of attribute_name_index
        self.len_off = len_off      # offset of the u4 attribute_length
        self.body_off = body_off    # offset of the first body byte
        self.length = length

    @property
    def end(self) -> int:
        return self.body_off + self.length


class Method:
    __slots__ = ("access", "name_index", "desc_index", "attributes")

    def __init__(self, access: int, name_index: int, desc_index: int) -> None:
        self.access = access
        self.name_index = name_index
        self.desc_index = desc_index
        self.attributes: List[Attribute] = []


class ClassFile:
    """Enough of a class file to find and rewrite constant-pool Utf8 entries and
    method Code attributes. Parsing is strict: any structural surprise raises."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.utf8: Dict[int, Utf8Entry] = {}
        self.methods: List[Method] = []
        self._parse()

    # -- parsing ---------------------------------------------------------- #

    def _parse(self) -> None:
        data = self.data
        if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
            raise PatchError("not a class file (bad magic)")
        self.minor = u2(data, 4)
        self.major = u2(data, 6)
        off = 8
        cp_count = u2(data, off)
        off += 2
        if cp_count < 1:
            raise PatchError("bad constant_pool_count")
        index = 1
        while index < cp_count:
            if off >= len(data):
                raise PatchError("truncated constant pool at index %d" % index)
            tag = data[off]
            off += 1
            if tag == 1:
                ln = u2(data, off)
                len_off = off
                off += 2
                if off + ln > len(data):
                    raise PatchError("truncated Utf8 at index %d" % index)
                self.utf8[index] = Utf8Entry(index, len_off, off, data[off:off + ln])
                off += ln
            elif tag in CP_FIXED:
                off += CP_FIXED[tag]
            else:
                raise PatchError("unknown constant-pool tag %d at index %d" % (tag, index))
            index += 2 if tag in CP_TWO_SLOT else 1

        self.access = u2(data, off)
        self.this_class = u2(data, off + 2)
        self.super_class = u2(data, off + 4)
        off += 6
        iface_count = u2(data, off)
        off += 2 + 2 * iface_count

        field_count = u2(data, off)
        off += 2
        for _ in range(field_count):
            off = self._skip_member(off, collect=None)

        method_count = u2(data, off)
        off += 2
        for _ in range(method_count):
            off = self._skip_member(off, collect=self.methods)

        self.class_attr_count = u2(data, off)

    def _skip_member(self, off: int, collect: Optional[List[Method]]) -> int:
        data = self.data
        access = u2(data, off)
        name_index = u2(data, off + 2)
        desc_index = u2(data, off + 4)
        off += 6
        attr_count = u2(data, off)
        off += 2
        method = Method(access, name_index, desc_index) if collect is not None else None
        for _ in range(attr_count):
            start = off
            name_idx = u2(data, off)
            len_off = off + 2
            declared = u4(data, len_off)
            body_off = len_off + 4
            if self.utf8_text(name_idx) == "Code":
                code_len = u4(data, body_off + 4)
                p = body_off + 8 + code_len
                exc = u2(data, p)
                p += 2 + 8 * exc
                nested = u2(data, p)
                p += 2
                for _ in range(nested):
                    p += 2
                    l = u4(data, p)
                    p += 4 + l
                length = p - body_off
            else:
                length = declared
            if body_off + length > len(data):
                raise PatchError("truncated attribute at 0x%x" % start)
            if method is not None:
                method.attributes.append(
                    Attribute(name_idx, start, len_off, body_off, length))
            off = body_off + length
        if method is not None:
            self.methods.append(method)
        return off

    def utf8_text(self, index: int) -> Optional[str]:
        entry = self.utf8.get(index)
        if entry is None:
            return None
        try:
            return entry.value.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def utf8_strings(self) -> List[str]:
        out = []
        for entry in self.utf8.values():
            try:
                out.append(entry.value.decode("utf-8"))
            except UnicodeDecodeError:
                continue
        return out


# --------------------------------------------------------------------------- #
# DER helpers (modulus extraction from SPKI / PKCS#1)
# --------------------------------------------------------------------------- #

def _der_tlv(buf: bytes, off: int) -> Tuple[int, bytes, int]:
    if off + 2 > len(buf):
        raise PatchError("truncated DER at 0x%x" % off)
    tag = buf[off]
    off += 1
    first = buf[off]
    off += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or off + count > len(buf):
            raise PatchError("bad DER length at 0x%x" % off)
        length = int.from_bytes(buf[off:off + count], "big")
        off += count
    else:
        length = first
    if off + length > len(buf):
        raise PatchError("DER length runs past buffer")
    return tag, buf[off:off + length], off + length


def modulus_from_der(der: bytes) -> bytes:
    """Accept either an X.509 SubjectPublicKeyInfo or a PKCS#1 RSAPublicKey."""
    tag, seq, _ = _der_tlv(der, 0)
    if tag != 0x30:
        raise PatchError("key blob is not a DER SEQUENCE (tag 0x%02x)" % tag)
    if not seq:
        raise PatchError("empty DER SEQUENCE")
    inner_tag = seq[0]
    if inner_tag == 0x30:                       # SPKI
        _t, _alg, after_alg = _der_tlv(seq, 0)
        tag, bits, _ = _der_tlv(seq, after_alg)
        if tag != 0x03:
            raise PatchError("SPKI: expected BIT STRING, got 0x%02x" % tag)
        if not bits or bits[0] != 0:
            raise PatchError("SPKI: BIT STRING has unused bits")
        tag, rsa_seq, _ = _der_tlv(bits, 1)
        if tag != 0x30:
            raise PatchError("SPKI: expected RSAPublicKey SEQUENCE")
        tag, modulus, _ = _der_tlv(rsa_seq, 0)
    elif inner_tag == 0x02:                     # bare PKCS#1
        tag, modulus, _ = _der_tlv(seq, 0)
    else:
        raise PatchError("unrecognised key DER (first inner tag 0x%02x)" % inner_tag)
    if tag != 0x02:
        raise PatchError("modulus is not an INTEGER (tag 0x%02x)" % tag)
    modulus = modulus.lstrip(b"\x00")
    if not modulus:
        raise PatchError("empty modulus")
    return modulus


# --------------------------------------------------------------------------- #
# key material classification
# --------------------------------------------------------------------------- #

def classify_key_material(text: str) -> Optional[Tuple[str, bytes]]:
    """Return (encoding, decoded) when text looks like RSA key material.

    encodings: spki_der | raw_modulus | decimal
    """
    stripped = "".join(text.split())
    if not stripped:
        return None

    if stripped.isdigit():
        if len(stripped) >= 300:
            return ("decimal", stripped.encode("ascii"))
        return None

    if len(stripped) % 4 != 0 or len(stripped) < 100:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped):
        return None
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None

    if decoded[:1] == b"\x30":
        try:
            modulus_from_der(decoded)
            return ("spki_der", decoded)
        except PatchError:
            pass
    if len(decoded) in KEY_DECODED_LENGTHS and decoded[0] & 0x80:
        return ("raw_modulus", decoded)
    return None


def describe_candidates(jar: str) -> List[Tuple[str, Utf8Entry, str, bytes]]:
    found: List[Tuple[str, Utf8Entry, str, bytes]] = []
    with zipfile.ZipFile(jar) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".class"):
                continue
            try:
                cf = ClassFile(zf.read(info.filename))
            except PatchError:
                continue
            for entry in cf.utf8.values():
                try:
                    text = entry.value.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                hit = classify_key_material(text)
                if hit is not None:
                    found.append((info.filename, entry, hit[0], hit[1]))
    return found


def detect_digests(jar: str) -> List[str]:
    hits: Set[str] = set()
    with zipfile.ZipFile(jar) as zf:
        for info in zf.infolist():
            for probe in DIGEST_PROBES:
                if probe.lower() in info.filename.lower().encode():
                    hits.add(probe.decode())
            if not info.filename.endswith(".class"):
                continue
            blob = zf.read(info.filename)
            for probe in DIGEST_PROBES:
                if probe in blob:
                    hits.add(probe.decode())
    return sorted(hits)


# --------------------------------------------------------------------------- #
# openssl bridge
# --------------------------------------------------------------------------- #

def run_openssl(args: Sequence[str], stdin: Optional[bytes] = None) -> bytes:
    exe = shutil.which("openssl")
    if exe is None:
        raise PatchError("openssl not found on PATH (needed for --privkey)")
    proc = subprocess.run(
        [exe, *args], input=stdin,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise PatchError("openssl %s failed: %s" % (
            " ".join(args[:2]), detail[-1] if detail else "exit %d" % proc.returncode))
    return proc.stdout


def load_key_material(pubkey_b64: Optional[str], privkey: Optional[str]
                      ) -> Tuple[bytes, bytes]:
    """Return (spki_der, modulus)."""
    if pubkey_b64 and privkey:
        raise PatchError("give either --pubkey or --privkey, not both")
    if privkey:
        if not os.path.isfile(privkey):
            raise PatchError("private key not found: %s" % privkey)
        spki = run_openssl(["pkey", "-in", privkey, "-pubout", "-outform", "DER"])
    elif pubkey_b64:
        try:
            spki = base64.b64decode("".join(pubkey_b64.split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise PatchError("--pubkey is not valid base64: %s" % exc)
    else:
        raise PatchError("key swap needs --pubkey <SPKI-BASE64> or --privkey <PEM>")
    modulus = modulus_from_der(spki)
    return spki, modulus


# --------------------------------------------------------------------------- #
# edit planning
# --------------------------------------------------------------------------- #

class Edit:
    __slots__ = ("class_name", "offset", "old", "new", "reason", "record", "key")

    def __init__(self, class_name: str, offset: int, old: bytes, new: bytes,
                 reason: str, record: dict) -> None:
        self.class_name = class_name
        self.offset = offset
        self.old = old
        self.new = new
        self.reason = reason
        self.record = record
        self.key = (class_name, offset)


def plan_keyswap(jar: str, spki: bytes, modulus: bytes
                 ) -> Tuple[Dict[str, bytes], List[Edit], List[str]]:
    spki_b64 = base64.b64encode(spki).decode("ascii")
    mod_b64 = base64.b64encode(modulus).decode("ascii")
    decimal = str(int.from_bytes(modulus, "big"))

    candidates = describe_candidates(jar)
    if not candidates:
        raise PatchError(
            "no RSA key material found in constant pools; run --list, or use --mode body")

    warnings: List[str] = []
    edits: List[Edit] = []
    by_class: Dict[str, List[Edit]] = {}
    new_blobs: Dict[str, bytes] = {}

    for class_name, entry, encoding, decoded in candidates:
        if encoding == "decimal":
            new_text = decimal
        elif encoding == "spki_der":
            new_text = spki_b64
        else:  # raw_modulus
            target_len = len(decoded)
            body = modulus
            if len(body) < target_len:
                body = b"\x00" * (target_len - len(body)) + body
            elif len(body) > target_len:
                warnings.append(
                    "%s: vendor modulus %d bytes, ours %d bytes (constant grows)"
                    % (class_name, target_len, len(body)))
            new_text = base64.b64encode(body).decode("ascii")

        new_bytes = new_text.encode("ascii")
        old_blob = struct.pack(">H", len(entry.value)) + entry.value
        new_blob = struct.pack(">H", len(new_bytes)) + new_bytes
        record = {
            "kind": "utf8_keyswap",
            "encoding": encoding,
            "old_len": len(entry.value),
            "new_len": len(new_bytes),
            "new_text": new_text,
        }
        edits.append(Edit(class_name, entry.len_off, old_blob, new_blob,
                          "keyswap %s constant -> attacker trust anchor" % encoding,
                          record))
        by_class.setdefault(class_name, []).append(edits[-1])

    with zipfile.ZipFile(jar) as zf:
        for class_name, class_edits in by_class.items():
            data = zf.read(class_name)
            new_blobs[class_name], new_offsets = splice(data, class_edits)
            for edit in class_edits:
                edit.record["offset_post"] = new_offsets[edit.key]
    return new_blobs, edits, warnings


def plan_body(jar: str) -> Tuple[Dict[str, bytes], List[Edit], List[str]]:
    scored: List[Tuple[int, str, ClassFile, List[Method]]] = []
    with zipfile.ZipFile(jar) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".class"):
                continue
            raw = zf.read(info.filename)
            try:
                cf = ClassFile(raw)
            except PatchError:
                continue
            strings = cf.utf8_strings()
            joined = "\n".join(strings)
            score = 0
            low_name = info.filename.lower()
            if "license" in low_name or "licence" in low_name:
                score += 4
            matched = []
            for method in cf.methods:
                name = cf.utf8_text(method.name_index) or ""
                desc = cf.utf8_text(method.desc_index) or ""
                if desc.endswith(")Z") and PRO_NAME_RE.match(name):
                    matched.append(method)
            score += min(len(matched), 2) * 3
            if "license_id" in joined or '"PRO"' in joined or "PRO edition" in joined:
                score += 3
            has_key = False
            for text in strings:
                if classify_key_material(text) is not None:
                    has_key = True
                    break
            if has_key:
                score += 4
            if matched:
                scored.append((score, info.filename, cf, matched))

    scored.sort(key=lambda row: (-row[0], row[1]))
    chosen = [row for row in scored if row[0] >= BODY_SCORE_THRESHOLD][:BODY_MAX_CLASSES]
    if not chosen:
        top = ", ".join("%s=%d" % (row[1], row[0]) for row in scored[:3]) or "none"
        raise PatchError(
            "no class scored >= %d for body mode (top: %s)" % (BODY_SCORE_THRESHOLD, top))

    warnings = ["body mode was chosen: it trusts every future licence blob"]
    edits: List[Edit] = []
    new_blobs: Dict[str, bytes] = {}
    with zipfile.ZipFile(jar) as zf:
        for score, class_name, cf, methods in chosen:
            data = zf.read(class_name)
            class_edits: List[Edit] = []
            for method in methods:
                code_attr = None
                for attr in method.attributes:
                    if cf.utf8_text(attr.name_index) == "Code":
                        code_attr = attr
                        break
                if code_attr is None:
                    continue
                old_blob = data[code_attr.start:code_attr.end]
                if len(old_blob) < 8:
                    continue
                max_locals = struct.unpack_from(">H", old_blob, 6)[0]
                name = cf.utf8_text(method.name_index) or "?"
                desc = cf.utf8_text(method.desc_index) or "?"
                new_blob = (
                    struct.pack(">H", code_attr.name_index)
                    + struct.pack(">I", 14)
                    + struct.pack(">H", 1)          # max_stack: iconst_1 pushes 1
                    + struct.pack(">H", max_locals)
                    + struct.pack(">I", 2)          # code_length
                    + b"\x04\xac"                   # iconst_1 ; ireturn
                    + struct.pack(">H", 0)          # exception_table_length
                    + struct.pack(">H", 0)          # attributes_count (drops frames)
                )
                record = {
                    "kind": "body_force_true",
                    "method": name,
                    "descriptor": desc,
                    "score": score,
                }
                class_edits.append(Edit(
                    class_name, code_attr.start, old_blob, new_blob,
                    "%s%s -> iconst_1; ireturn" % (name, desc), record))
            if not class_edits:
                continue
            edits.extend(class_edits)
            new_blobs[class_name], new_offsets = splice(data, class_edits)
            for edit in class_edits:
                edit.record["attr_offset_post"] = new_offsets[edit.key]
    return new_blobs, edits, warnings


def splice(data: bytes, edits: List[Edit]) -> Tuple[bytes, Dict[Tuple[str, int], int]]:
    """Apply non-overlapping edits, returning new bytes and post-edit offsets."""
    ordered = sorted(edits, key=lambda e: e.offset)
    out = bytearray()
    pos = 0
    new_offsets: Dict[Tuple[str, int], int] = {}
    for edit in ordered:
        if edit.offset < pos:
            raise PatchError("overlapping edits at 0x%x" % edit.offset)
        out += data[pos:edit.offset]
        new_offsets[edit.key] = len(out)
        out += edit.new
        pos = edit.offset + len(edit.old)
    out += data[pos:]
    return bytes(out), new_offsets


# --------------------------------------------------------------------------- #
# jar rewriting
# --------------------------------------------------------------------------- #

def rebuild_jar(src: str, dst: str, replacements: Dict[str, bytes],
                drop: Set[str]) -> None:
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for info in zin.infolist():
            if info.filename in drop:
                continue
            if info.filename in replacements:
                payload = replacements[info.filename]
            else:
                payload = zin.read(info.filename)
            clone = zipfile.ZipInfo(info.filename, info.date_time)
            clone.compress_type = info.compress_type
            clone.external_attr = info.external_attr
            clone.internal_attr = info.internal_attr
            clone.create_system = info.create_system
            clone.comment = info.comment
            clone.extra = info.extra
            zout.writestr(clone, payload)


def signature_entries(jar: str) -> List[str]:
    with zipfile.ZipFile(jar) as zf:
        return [i.filename for i in zf.infolist()
                if SIG_ENTRY_RE.match(i.filename) or i.filename in EXTRA_STRIP]


# --------------------------------------------------------------------------- #
# input resolution
# --------------------------------------------------------------------------- #

def resolve_input(path: str) -> str:
    if not os.path.exists(path):
        raise PatchError("input not found: %s" % path)
    if os.path.isfile(path):
        return os.path.abspath(path)
    hits = []
    for name in sorted(os.listdir(path)):
        if not name.lower().endswith(".jar"):
            continue
        candidate = os.path.join(path, name)
        try:
            with zipfile.ZipFile(candidate) as zf:
                if MAIN_CLASS in zf.namelist():
                    hits.append(candidate)
        except zipfile.BadZipFile:
            continue
    if not hits:
        raise PatchError("no *.jar containing %s under %s" % (MAIN_CLASS, path))
    if len(hits) > 1:
        raise PatchError("ambiguous input, %d jars match: %s"
                         % (len(hits), ", ".join(os.path.basename(h) for h in hits)))
    return os.path.abspath(hits[0])


# --------------------------------------------------------------------------- #
# actions
# --------------------------------------------------------------------------- #

def do_list(jar: str) -> int:
    print("jar    : %s" % jar)
    print("sha256 : %s" % sha256_file(jar))
    try:
        with zipfile.ZipFile(jar) as zf:
            names = zf.namelist()
            major = None
            if MAIN_CLASS in names:
                head = zf.read(MAIN_CLASS)[:8]
                if len(head) >= 8 and head[:4] == b"\xca\xfe\xba\xbe":
                    major = struct.unpack_from(">H", head, 6)[0]
    except zipfile.BadZipFile as exc:
        raise PatchError("not a zip/jar: %s" % exc)
    print("main class present: %s" % ("yes" if MAIN_CLASS in names else "NO"))
    print("class file major : %s" % (major if major is not None else "unknown"))
    print()

    candidates = describe_candidates(jar)
    print("key-material candidates: %d" % len(candidates))
    for class_name, entry, encoding, decoded in candidates:
        print("  %s" % class_name)
        print("    0x%08x  utf8  len=%d  %s  bytes=%d  sha256=%s  %s"
              % (entry.value_off, len(entry.value), encoding, len(decoded),
                 sha256_bytes(decoded)[:16], preview(entry.value)))
    print()

    digests = detect_digests(jar)
    print("digest strings: %s" % (", ".join(digests) if digests else "none detected"))
    print("  -> use the matching --alg in keygen_burp.py (sha1/sha256/md5)")
    print()

    sigs = signature_entries(jar)
    print("signature entries to strip: %d" % len(sigs))
    for name in sigs:
        print("  %s" % name)

    if not candidates:
        print()
        print("note: no key material found; --mode body is the fallback")
    print()
    print("OK: diagnosis complete, jar untouched")
    return 0


def do_restore(jar: str) -> int:
    bak = backup_path(jar)
    if not os.path.isfile(bak):
        raise PatchError("no backup to restore from: %s" % bak)
    shutil.copy2(bak, jar)
    side = sidecar_path(jar)
    if os.path.isfile(side):
        os.unlink(side)
    got = sha256_file(jar)
    print("restored %s from %s" % (os.path.basename(jar), os.path.basename(bak)))
    print("sha256 now %s (backup left in place)" % got)
    print("OK: byte-exact restore complete")
    return 0


def do_verify(jar: str) -> int:
    side = sidecar_path(jar)
    if not os.path.isfile(side):
        raise PatchError("no sidecar at %s; nothing recorded to verify" % side)
    try:
        with open(side, "r", encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise PatchError("unreadable sidecar: %s" % exc)

    problems = 0
    got = sha256_file(jar)
    if got != state.get("post_sha256"):
        print("  [FAIL] jar sha256 %s != recorded post %s"
              % (got, state.get("post_sha256")))
        problems += 1
    else:
        print("  [ ok ] jar matches recorded post-edit sha256")

    with zipfile.ZipFile(jar) as zf:
        names = set(zf.namelist())
        by_class: Dict[str, List[dict]] = {}
        for record in state.get("edits", []):
            by_class.setdefault(record["class"], []).append(record)
        for class_name, records in by_class.items():
            if class_name not in names:
                print("  [FAIL] %s missing from jar" % class_name)
                problems += 1
                continue
            blob = zf.read(class_name)
            for record in records:
                if record["kind"] == "utf8_keyswap":
                    off = record.get("offset_post")
                    want = record["new_text"].encode("ascii")
                    ok = (off is not None and off + 2 + len(want) <= len(blob)
                          and struct.unpack_from(">H", blob, off)[0] == len(want)
                          and blob[off + 2:off + 2 + len(want)] == want)
                    if ok:
                        print("  [ ok ] %s 0x%08x anchor %s present"
                              % (class_name, off, record["encoding"]))
                    else:
                        print("  [FAIL] %s 0x%s anchor %s absent"
                              % (class_name, off, record["encoding"]))
                        problems += 1
                else:
                    off = record.get("attr_offset_post")
                    ok = (off is not None and off + 18 <= len(blob)
                          and struct.unpack_from(">I", blob, off + 2)[0] == 14
                          and blob[off + 14:off + 16] == b"\x04\xac"
                          and struct.unpack_from(">H", blob, off + 16)[0] == 0)
                    if ok:
                        print("  [ ok ] %s %s%s returns true"
                              % (class_name, record["method"], record["descriptor"]))
                    else:
                        print("  [FAIL] %s %s%s body not forced"
                              % (class_name, record["method"], record["descriptor"]))
                        problems += 1

    leftovers = signature_entries(jar)
    if leftovers:
        print("  [FAIL] signature entries remain: %s" % ", ".join(leftovers))
        problems += 1
    else:
        print("  [ ok ] no META-INF signature entries remain")

    if problems:
        print("FAIL: %d assertion(s) failed" % problems)
        return 1
    print("OK: %d edit(s) verified, jar is authorized" % len(state.get("edits", [])))
    return 0


def do_patch(jar: str, args: argparse.Namespace) -> int:
    side = sidecar_path(jar)
    current = sha256_file(jar)

    if os.path.isfile(side):
        try:
            with open(side, "r", encoding="utf-8") as fh:
                prior = json.load(fh)
        except (OSError, json.JSONDecodeError):
            prior = None
        if prior is not None and prior.get("post_sha256") == current:
            print("jar    : %s" % jar)
            print("sha256 : %s" % current)
            print("OK: already patched (sidecar matches), nothing to do")
            return 0
        if prior is not None and not args.force:
            raise PatchError(
                "jar changed since last patch (recorded %s, found %s); rerun with --force"
                % (prior.get("post_sha256"), current))

    if args.expect is not None:
        if current != args.expect.lower():
            if not args.force:
                raise PatchError(
                    "hash gate: expected %s, found %s (rerun with --force to override)"
                    % (args.expect.lower(), current))
            print("warning: hash gate overridden, expected %s found %s"
                  % (args.expect.lower(), current))

    if args.mode == "keyswap":
        spki, modulus = load_key_material(args.pubkey, args.privkey)
        new_blobs, edits, warnings = plan_keyswap(jar, spki, modulus)
        print("pubkey SPKI b64 (feed to keygen_burp --privkey pair):")
        print("  %s" % base64.b64encode(spki).decode("ascii"))
    else:
        new_blobs, edits, warnings = plan_body(jar)

    for warning in warnings:
        print("warning: %s" % warning)
    if not edits:
        raise PatchError("planned 0 edits")

    drop = set(signature_entries(jar))

    print()
    for edit in edits:
        print("  %s" % edit.class_name)
        print("0x%08x  %s -> %s  (%s)"
              % (edit.offset, preview(edit.old), preview(edit.new), edit.reason))
    for name in sorted(drop):
        print("strip    %s  (signature manifest, JVM verifies against the old key)" % name)
    print()

    if args.dry_run:
        print("DRY RUN: %d class edit(s), %d entry drop(s), %d class(es) rewritten"
              % (len(edits), len(drop), len(new_blobs)))
        print("OK: dry run complete, jar untouched")
        return 0

    bak = backup_path(jar)
    if not os.path.isfile(bak):
        shutil.copy2(jar, bak)
        print("backup   %s" % bak)
    else:
        print("backup   %s (existing, kept)" % bak)

    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix=".burppatch-", suffix=".jar", dir=os.path.dirname(jar) or ".")
    os.close(tmp_fd)
    try:
        rebuild_jar(jar, tmp_path, new_blobs, drop)
        with zipfile.ZipFile(tmp_path) as check:
            broken = check.testzip()
            if broken is not None:
                raise PatchError("rewritten jar fails CRC on %s" % broken)
        os.replace(tmp_path, jar)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    post = sha256_file(jar)
    state = {
        "schema": SCHEMA,
        "jar": os.path.basename(jar),
        "mode": args.mode,
        "pre_sha256": current,
        "post_sha256": post,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "edits": [edit.record for edit in edits],
        "stripped": sorted(drop),
    }
    with open(side, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
        fh.write("\n")

    print("state    %s" % side)
    print("sha256   %s -> %s" % (current, post))
    print("OK: patched %s (%s, %d edit(s), %d entry drop(s))"
          % (os.path.basename(jar), args.mode, len(edits), len(drop)))
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="patch_burp.py",
        description="Swap the Burp Suite Pro embedded RSA trust anchor "
                    "(mode=keyswap) or force licence predicates (mode=body).",
        epilog="Dry run is the default posture; add --apply to write.")
    p.add_argument("--input", required=True, metavar="PATH",
                   help="jar file, or a directory to auto-discover the jar in")
    p.add_argument("--expect", metavar="SHA256",
                   help="abort unless the input has this SHA-256 (unless --force)")
    p.add_argument("--mode", choices=("keyswap", "body"), default="keyswap",
                   help="keyswap replaces the trust anchor; body forces predicates")
    p.add_argument("--pubkey", metavar="B64",
                   help="replacement public key as SPKI base64")
    p.add_argument("--privkey", metavar="PEM",
                   help="replacement private key PEM; public half is derived via openssl")
    p.add_argument("--list", action="store_true",
                   help="diagnose only: candidates, offsets, encodings, digests; then exit")
    p.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")
    p.add_argument("--apply", action="store_true", help="actually rewrite the jar")
    p.add_argument("--restore", action="store_true", help="byte-exact restore from <file>.orig")
    p.add_argument("--verify", action="store_true", help="re-check recorded edits; exit 0 == ok")
    p.add_argument("--force", action="store_true",
                   help="override the hash gate and a changed-jar mismatch")
    return p


def main(argv: Sequence[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dry_run and args.apply:
        fail("--dry-run and --apply are mutually exclusive")
    if args.apply:
        args.dry_run = False
    else:
        args.dry_run = True

    try:
        jar = resolve_input(args.input)
        if args.restore:
            return do_restore(jar)
        if args.list:
            return do_list(jar)
        if args.verify:
            return do_verify(jar)
        return do_patch(jar, args)
    except PatchError as exc:
        fail(str(exc))
        return 1
    except (zipfile.BadZipFile, OSError, struct.error) as exc:
        fail("%s: %s" % (type(exc).__name__, exc))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))