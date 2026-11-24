# re_burp — Burp Suite Pro 2026.11.2 (Build 55152)

Four byte patches take a stock jar to fully authorized Professional. Jar is
**unsigned** in this build, so no signature entries need stripping and no
`SecurityException` risk exists.

| # | Target | Offset | Body | Why | Confidence |
|---|---|---|---|---|---|
| 1 | `burp/Zhxf.Zr(String)Z` | 0x10e1 | `04 ac` | Signature verifier returns true | confirmed |
| 2 | `burp/Zn15.Zl(Zhzs,String)Z` | 0x1e2b | `04 ac` | Licence accept/reject returns true | confirmed |
| 3 | `burp/Zu6.ZG(String,int)Object[]` | — | `Object[]{caption,key,Long,Integer}` + 12 appended CP entries | Bypasses the whole KlassMaster codec chain and hands `Zug1.Zx` a real array so `Zwx`/`Zudh` gets built | confirmed |
| 4 | `burp/Ztk8.Ze(String)V` | — | `b1` (return) | Manual-activation response validator becomes a no-op | confirmed |

## The chain

`Zq9j.ZR`/`Zq` → `Zo8.ZI`/`Ze` → `Zldm.ZF` → `Ztk8.ZF` → `Zu6.ZG` → reflective
KlassMaster dispatch into `Zekc`, which builds a 32-char key from `BigInteger`
field constants and re-dispatches by reflection. Patch 3 cuts the chain at `ZG`;
patch 4 removes the response validator that `Ze` runs before it.

`Zug1.Zx` is the contract: `Object[]{String caption, String allocationKey, Long
expiryMillis, Integer flags, [String], [String], [String]}` → `new Zwx(...)`,
which implements `Zudh`. Everything past index 3 is optional.

## Activation

1. `java -noverify -jar burpsuite_pro.jar`
2. Enter any key → Next
3. Online activation fails (no vendor server for a fake key) → **Manual activation**
4. **Paste response** → paste any text → Next
5. Temporary project → Next

Licence persists in Burp's user config; later launches re-validate through
patches 1–2 and need no input.

## Gotchas

- `-noverify` is required: patch bodies drop `StackMapTable`, and the split
  verifier is useless here.
- Attribute length must be `8 + code_len + 4`, not a constant. Getting this
  wrong yields `ClassFormatError: Code segment has wrong length`.
- `ldc2_w` pushes two slots — `max_stack` must account for it (`VerifyError:
  Operand stack overflow` otherwise).
- Burp locks the jar: **close it before any `--apply`**. A failed apply leaves
  `tmp*.jar` behind, which makes `--input .` ambiguous — `rm -f tmp*.jar`.
- `Zo8.ZI` returning a bare `Zeqh` compiles and verifies but breaks startup: the
  side effect `Zhkt.ZQ(z)` never runs, so no licence reaches state. That's why
  patch 3 synthesises the array instead of returning a constant result.

## Restore

`py patch_licence.py --input burpsuite_pro.jar --restore` (byte-exact, from
`.orig`). `burpsuite_pro.jar.orig` is the pristine vendor jar — keep it.

## Updates

New version: drop in the new jar, keep the old `.orig`, update `EXPECT` in
`reapply.sh`, run `--list` to confirm the class names still exist, then
`reapply.sh`. Obfuscated names rotate between releases; if a target is missing,
re-derive it from `Zq9j.ZR` → `Zo8.ZI` as done here.