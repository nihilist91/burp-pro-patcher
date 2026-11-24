# notes - Burp Suite Desktop 2026.11.2 (Build 55152)

Four byte patches take a stock jar to fully authorized Professional. The jar is
**unsigned** in this build: no signature entries to strip, no `SecurityException`
risk, nothing to re-sign.

| # | Target | Offset | Body | Why | Confidence |
|---|---|---|---|---|---|
| 1 | `burp/Zhxf.Zr(String)Z` | 0x10e1 | `04 ac` | signature verifier returns true | confirmed |
| 2 | `burp/Zn15.Zl(Zhzs,String)Z` | 0x1e2b | `04 ac` | licence accept/reject returns true | confirmed |
| 3 | `burp/Zu6.ZG(String,int)Object[]` | - | `Object[]{caption, key, Long, Integer}` plus 12 appended CP entries | bypasses the codec chain and hands `Zug1.Zx` a real array | confirmed |
| 4 | `burp/Ztk8.Ze(String)V` | - | `b1` | manual-activation response validator becomes a no-op | confirmed |

## The chain

`Zq9j.ZR` / `Zq9j.Zq` -> `Zo8.ZI` / `Zo8.Ze` -> `Zldm.ZF` -> `Ztk8.ZF` ->
`Zu6.ZG` -> reflective KlassMaster dispatch into `Zekc`, which builds a 32-char
key from `BigInteger` field constants and re-dispatches by reflection. There is
no plaintext public key anywhere, so a key swap is not available and a keygen
has no anchor to sign against.

Patch 3 cuts the chain at `ZG`. Patch 4 removes the response validator that
`Ze` runs in front of it. Patches 1 and 2 are belt and braces: they cover any
path that still reaches the verifier, including stored-licence revalidation.

## The array contract

`Zug1.Zx` is the consumer:

`Object[]{String caption, String allocationKey, Long expiryMillis, Integer
flags, [String], [String], [String]}` -> `new Zwx(...)`, which implements
`Zudh`. Everything past index 3 is optional and `null` is fine.

## Byte-level gotchas

- `Code` attribute length is `8 + code_len + 4`, never a constant. Hardcoding 14
  for an 8-byte body gives `ClassFormatError: Code segment has wrong length`.
- `ldc2_w` pushes two operand-stack slots. `max_stack` must account for the
  whole peak, not the visible depth.
- `max_locals` is read at body offset 2 and must be preserved. Reading it at
  offset 6 returns `max_stack`, which is silently wrong until it isn't.
- Patch bodies drop `StackMapTable`. That is legal for straight-line code with
  no branch targets, but it means `-noverify` is mandatory.
- `Zo8` has a Code attribute whose declared length is 6 bytes short of its own
  `code_length`. Trusting the declared length desyncs the parser and produces a
  bogus attribute offset. `patch_burp._skip_member` derives Code length from
  `code_length` instead of trusting the field.

## Why not the obvious routes

- **Key swap / keygen** - the verifier's public key is assembled at runtime from
  encrypted fragments; there is no constant to replace.
- **Bare success type from `Zo8.ZI`** - compiles and verifies, but startup dies
  silently. `ZI` normally calls `Zhkt.ZQ(z)` inside a `synchronized` block; a
  bare `Zeqh` skips it, so no licence reaches state and the UI builder NPEs.
  Synthesising the array at `ZG` keeps every side effect.
- **Full decompile** - the jar is KlassMaster obfuscated; a round trip loses the
  vendor's frames for a much larger diff than four methods.

## Restore

`py patch/patch_licence.py --input burpsuite_pro.jar --restore`

Byte-exact, from `.orig`. Keep `burpsuite_pro.jar.orig` - it is the pristine
vendor jar and the only thing that makes updates cheap.

## Updating

Class names are obfuscated and rotate every release. On a new version, refresh
`TARGET_SHA256`, run `--list` on each target, and if one is gone re-derive it by
following `Zq9j.ZR` -> `Zo8.ZI` -> `Zldm` -> `Ztk8` -> `Zu6`.

## Known limits

- Only the exact pinned build is hash-gated. Other versions will apply, but
  offsets and names are unverified.
- Online activation still fails; the manual-activation path is the only one.
- Pro-only server features that call out (Collaborator, Burp AI credits) are
  unaffected by these patches and still need real credentials.
