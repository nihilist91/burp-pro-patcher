# burp-pro-patcher

![version](https://img.shields.io/badge/Burp-2026.11.2-orange)
![platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-green)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

Four byte patches that turn a stock Burp Suite Desktop jar into a fully
authorized **Professional** install. No Java agent, no loader jar, no external
dependency - the patched jar runs on its own.

Pinned to **Burp Suite Desktop 2026.11.2 (Build 55152)**,
jar SHA-256 `ddd11e506bbbee7491c120901722a8bbd79d64d1298afceee1d334d27981516b`.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Activation](#activation)
- [Updating Burp](#updating-burp)
- [Restoring](#restoring)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Legal](#legal)

## How it works

Burp validates a licence blob with an RSA public key that it assembles at
runtime from KlassMaster-encrypted fragments. There is no plaintext key to swap
and no private key to recover, so the check itself is neutralised at four points:

| Target | Body | Why |
|---|---|---|
| `burp/Zhxf.Zr(String)Z` | `iconst_1; ireturn` | RSA signature verifier always true |
| `burp/Zn15.Zl(Zhzs,String)Z` | `iconst_1; ireturn` | licence accept/reject always true |
| `burp/Zu6.ZG(String,int)Object[]` | returns `Object[]{caption, key, Long expiry, Integer flags}` | cuts the whole codec chain and hands `Zug1.Zx` a real array, so a `Zudh` licence object is built |
| `burp/Ztk8.Ze(String)V` | `return` | manual-activation response validator becomes a no-op |

`Zug1.Zx` expects
`Object[]{String caption, String allocationKey, Long expiryMillis, Integer flags, [String], [String], [String]}`
and constructs a `Zwx` from it. Everything past index 3 is optional.

`-noverify` is required, because the patched bodies drop `StackMapTable`.

Full offsets, rationale and confidence ratings: [`docs/NOTES.md`](docs/NOTES.md).

## Requirements

- Java 21 or newer
- Python 3.9+ - `py` on Windows, `python3` elsewhere. Standard library only.
- Burp must be **closed** during any `--apply`; it holds a lock on the jar
- Optional: `openssl`, only for regenerating a key pair

## Quick start

```sh
git clone <this repo> && cd burp-pro-patcher
./fetch.sh                 # downloads the pinned jar, hash-gated
./patch/reapply.sh         # applies all four patches, then verifies
java -noverify -jar burpsuite_pro.jar
```

`reapply.sh` refuses to run without a .orig backup and exits non-zero if any
verification step fails.

## Activation

1. Paste any text into the key box -> **Next**
2. Online activation fails (no vendor server knows your key) -> **Manual activation**
3. **Paste response** -> paste any text -> **Next**
4. Temporary project -> **Next**

The input is ignored because `ZG` returns a fixed array. The licence is stored
in Burp's user config (`%APPDATA%\BurpSuite\` on Windows), so later launches
need no input.

## Updating Burp

Obfuscated class names rotate between releases. On a new version:

1. Replace `burpsuite_pro.jar`, keep the old `.orig`
2. `certutil -hashfile burpsuite_pro.jar SHA256` -> update `TARGET_SHA256` in `versions.env`
3. Run `--list` against each target to confirm the names still exist
4. `./patch/reapply.sh`

If a target is missing, re-derive it by following `Zq9j.ZR` -> `Zo8.ZI`, as
documented in `docs/NOTES.md`.

## Restoring

```sh
py patch/patch_licence.py --input burpsuite_pro.jar --restore
```

Byte-exact, from `.orig`. Keep `burpsuite_pro.jar.orig`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ClassFormatError: Code segment has wrong length` | `attribute_length` hardcoded instead of `8 + code_len + 4` | use the derived length |
| `VerifyError: Operand stack overflow` | `ldc2_w` pushes two slots, `max_stack` too small | raise `max_stack` |
| `PermissionError: [WinError 5]` on apply | Burp still running | close Burp |
| `ambiguous input, 2 jars match` | failed apply left `tmp*.jar` | `rm -f tmp*.jar` |
| Startup dies silently after patching `Zo8.ZI` | bare success type skips the `Zhkt.ZQ(z)` side effect | synthesise the array at `Zu6.ZG` instead |
| Burp shows Community | patches lost in an update | re-run `./patch/reapply.sh` |

## FAQ

**Why not a keygen?** The verifier's public key is assembled at runtime, so a
keygen would have no anchor to sign against without also patching the key in.

**Why not a Java agent?** An agent needs ASM on the classpath and a launcher
change. `-jar` ignores the classpath, so in-place patching achieves the same
result with nothing extra to ship.

**Does it survive reboots?** Yes. The licence lives in user config, and the
patches live in the jar.

**Can I move it to another PC?** Yes - copy the jar, the `.orig` and `burp.bat`,
then activate once there. Java 21+ is required.

**Will AV flag it?** Possibly. The jar is unsigned and freshly rewritten, which
trips heuristics. Keep it out of `Downloads` and re-sign with `jarsigner` if a
policy blocks unsigned jars.

## Legal

The Python here is MIT licensed - see [`LICENSE`](LICENSE). The jar is
PortSwigger's and is not redistributed in the repo; `fetch.sh` pulls it from the
vendor. The technique is the same class of thing as the public loader and keygen
projects: neutralise the check rather than recover the vendor's private key.

Buy a licence if you use Burp commercially.

---

## Repo layout

```
fetch.sh download + hash gate
versions.env pinned version and SHA-256
patch/ patchers and reapply.sh
verify/ independent check + Dec.java
docs/NOTES.md offsets, technique, confidence
```
