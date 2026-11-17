# Fidelity instrument: per-function equality of a candidate build against the shipping kernel (host-only; nothing published, dispatched or flashed)

Question it answers: for each function of a built kernel object (`.o`), does the compiled code equal the function of the same name in the shipping image
(`shipping-img/Image.raw`, Linux 4.9.190+, clang 9.0.3)? Used to choose sources by evidence (which tree, which revision) instead of by lineage guesses.

## Files

| file | purpose |
|---|---|
| `fidelity_lib.py` | AArch64 normalizer, shipping reader (kallsyms ranges), ELF object reader, diff classifier. stdlib only. |
| `make_fingerprints.py` | `Image.raw` + `kallsyms.txt` -> `shipping-function-fingerprints.json.gz` (hash-only). |
| `shipping-function-fingerprints.json.gz` | the database: 52,811 functions, 52,079 names, 513 alias entries; **1.49 MB gzipped (4.5 MB raw)**. Per function: two digests, word count, string-hash list, shipping VA. No shipping bytes. |
| `object_fidelity.py` | objects (`.o` files or dirs) vs the database -> receipt JSON. Optional `--explain IMAGE KALLSYMS` (private image) classifies each different function; `--expect FILE` turns a unit into PASS/FAIL. |
| `test_fidelity.py` | 7 unit tests + `--measure` (agreement, mutation sensitivity, masked-field invariance). |
| `cc.sh`, `host_compile.sh` | host build recipe (shipping compiler, kernel KBUILD flags, `-g`); `KTREE=` selects the header tree. |
| `summarize_receipts.py` | receipts -> markdown tables (`receipts/TABLES.md`). |
| `receipts/` | all receipts of this round (units with 4.9.117 and 4.9.190 headers, panels, 8 Lenovo sensors, ov5675 candidate, AC107 candidate, measurements). |
| `CI-STEP.md` | CI step design (not applied to any workflow). |

## Normalization (what is compared)

Per function, the instruction words are normalized, then hashed: `digest = sha1(normalized words || NUL || newline-joined branch/call target names)[:12]`.
The same code normalizes the shipping function (from the image) and the object function (from the `.o`), so no relocation processing is needed on the shipping side.

Masked (value replaced by zero), because layout, not source, decides it:
- `B`/`BL`/`B.cond`/`CBZ`/`CBNZ`/`TBZ`/`TBNZ` immediates **when the target is outside the function or the word is relocated**; branches inside the function keep their offset (loop and diamond shape stay compared).
- `ADRP` and `ADR` immediates; `LDR (literal)` immediate.
- `ADD xd, xn, #imm12` and `LDR/STR (unsigned offset)` imm12 **when `xn` still holds an ADRP page base**. The page-base state is tracked per function: set by `ADRP`, copied by `MOV`, ended when the register is rewritten or clobbered by a call (caller-saved), carried along forward branches (so cold blocks placed after `RET` keep the state of the branch that reaches them). A relocated word the patterns miss is masked by its relocation type in the object (counted in `normalize.fallbacks`; the shipping side has no such information).
- Trailing `NOP`/zero padding: a second, trimmed digest is stored/checked; either may match.

Kept (compared): opcodes, registers, all other immediates, instruction count and order, intra-function branch shape; **branch/call target names** in order (shipping: kallsyms name at the target, aliases mapped to the smallest alias; object: relocation symbol, or the function at the section+addend, or the function at the unrelocated target position; `.isra/.constprop/.part/.cold` suffixes stripped).
Strings: `ADRP+ADD` string references are hashed per function (shipping: printable NUL-terminated text at the resolved address; object: `.rodata*` section content) and reported as `strings_in_shipping` (informational, not part of the digest).

Verdict per object function, by name in the database: `equal` (digest matches the only shipping function of that name), `equal_ambiguous` (matches one of several same-name shipping functions, typical for `static` names such as `lcm_init`, `open`, `probe`), `different` (name present, no digest equal), `absent` (name not in the shipping image: inlined, renamed, `__exit`, or not part of the build). Per object: `ALL-EQUAL`, `PARTIAL`, `NONE-EQUAL`, `NO-FUNCTIONS`.
For ambiguity the receipt carries the matching shipping VAs and a `single_region` window: the smallest shipping address window that holds one matching instance of every equal function. An object whose functions all fall in one ~5-15 KB window is one translation unit of the shipping image.

## What can legitimately differ (not source differences)

- Compiler, `-g` (the stock config has `CONFIG_DEBUG_INFO=y`; without `-g` the scheduler orders instructions differently and nothing matches), flags, config macros, **header generation** (see measured results below).
- `__init`/`__exit`: `__exit` functions of built-in code are discarded (absent). `__init` text is still in the image file.
- Boot-time patching (alternatives, jump labels, `paravirt`-like) happens in memory; the image file holds the unpatched build output, so it compares equal to the object (no allowance needed).
- Per-directory `ccflags` that the host recipe does not apply (none were found for the units measured here).

## Measured baseline (honest thresholds)

Ground truth: the AC107 fork's word-by-word comparison (`recon-ac107/cmpobj.py`) of 3 host objects (`ac107-cand.o`, `ac107-len.o`, `codec6357.o`).
- 182 functions compared, **180 agree, 0 false-different**. The two disagreements (`ac107_i2c_detect`, `ac107_store` in the public ac107.c build) are cases where the older tool flagged an intra-object `BL` whose distance changed because another function in that object has a different size; call target names are equal and the code is equal. The instrument calls them equal, which is the correct reading, so they are not counted as errors.
- Control files: `ac107-cand.o` 21 of 21 (+`ac107_exit` absent, `__exit`), `ocp2131.o` 8 of 8 (+exit absent), matching the fork's byte-exact claims; public `ac107.c` without the one-line fix: 20 equal, 1 different (`ac107_i2c_probe`, instruction-count 122 vs 137) as the fork found; `codec6357.o`: 147 equal, 8 different, 3 absent, identical to the fork's 147/8/2 (+`mtk_mt6357_codec_exit`).
- Mutation sensitivity: changing one unmasked word of each of the 29 equal functions of `ac107-cand.o` and `ocp2131.o` made all 29 different (29/29).
- Masked-field invariance: scrambling exactly the masked bits of relocated words kept 6 of 7 functions equal. The seventh scrambles an unrelocated external `BL`, whose new target lands inside the function and is then compared on purpose.
- Remaining false-different risk: a register that is an ADRP page base but copied through something other than `MOV` (e.g. `ADD xd, xn, #0`), or code whose page-base tracking differs between object and image; three such cases were found and fixed during calibration (cold blocks after `RET`, register copy, call clobber). Treat a lone `different` with a 1-6 word difference as "inspect with `--explain`", not as proof of different source.

## Host results (Lenovo 4.9.117 transplant units, panel/sensor candidates)

Full per-object tables: `receipts/TABLES.md`. Summary (equal counts include ambiguous; compiler = shipping clang 9.0.3):

| set | functions | equal | different | absent |
|---|---|---|---|---|
| 35 transplant-unit objects, Lenovo 4.9.117 headers | 884 | 759 | 104 | 21 |
| same, philmb 4.9.190 headers | 884 | 767 | 96 | 21 |
| 2 panel candidates (hx83102p_inx, hx83102e_2nd; stub display headers) | 32 | 32 | 0 | 0 |
| Lenovo-drop hx83102e and ft8201 panel sources | 28 | 22 | 6 | 0 |
| ov5675 candidate (x606f source, OTP off, "ofilm ov5675 5m") | 11 | 11 | 0 | 0 |
| 8 Lenovo-drop sensor drivers (9 files; the unbuilt second ov13b10 file included) | 104 | 72 | 32 | 0 |
| AC107 candidate | 22 | 21 | 0 | 1 (`ac107_exit`) |

Reading by unit (4.9.190-header run unless stated; "different" is the first-hunk class from `--explain`):
- **Equal or nearly equal (Lenovo 4.9.117 source is the shipping revision for these files):** `ocp2131.c` 8/8, `sgm37604a_driver.c` 8/8, `fs/exfat` (api, bitmap, cache all equal; blkdev 6/7; core 105/124, nls 5/8, oal 3/4, super 45/51), `dbmdx` (cdev, customer, i2s, snd-codec, snd-pcm equal; `dbmdx.c` 219/252, `uart` 40/41), `wusb3801x.c` 28/30 with 4.9.117 headers and 29/30 with 4.9.190 headers (the 30th is an absent `__exit`), `hqsys_misc.c` 7/7 with 4.9.190 headers (4/7 with 4.9.117 headers: header-generation effect, the differences are `set_bit` calls that only the shipping build emits as calls).
- **Different revision or flags (not the shipping source as-is):** `hall_switch.c` (shipping calls `irq_set_irq_wake` and `input_event` where the Lenovo source does not: `hall_switch_probe` 127 vs 140 words, `hall_irq_handler` 27 vs 33), `sx9310.c` (21 of 27 differ; `instruction-count` and `mixed`), `hqsysfs.c` (3 functions 1 word short, `hq_harware_init` 16 words short), `fusb301a.c` (shipping has no `dual_role_instance_*`/`devm_dual_role_*` calls: built without the dual-role code, a config or revision difference), `flashlights-sywt78.c` (`sywt78_probe` 1 word).
- **Panels:** both recovered candidates are equal in all 16 functions; ambiguous names resolve to one 5 KB shipping window each (p_inx `ffffff80086cc334..86cd680`, 2nd `..86ce8a8..86cfe40`); the Lenovo `hx83102e`/`ft8201` sources differ in `lcm_get_params`, `lcm_init`, `lcm_suspend` (shipping calls `FT8201_gesture_status`, `fts_tp_enter_sleep_mode`, OCP2131 GPIO disables there), i.e. the shipping panels are newer revisions, as the panel fork found.
- **ov5675 candidate:** every function equal; all 10 unambiguous VAs inside the shipping OV5675 block (`ffffff800870dd88..ffffff8008711460`, block size 16204 B). Needs `-DOV5675_SENSOR_ID=0x5675` (the Lenovo header has no such id: the transplant must add it). Register tables and `imgsensor_info` data are compared by the sensor fork's separate data checks, not by this code-only instrument.
- **Lenovo sensors:** `s5k4h7yxqtech` 8/12, `s5k4h7yxfront`/`lcetron` 7/14 each, `gc5035*` 9-10/11, `ov13b10qtech` 9/10; the Lenovo `qtech` source is not the shipping revision for 4 functions (consistent with the sensor fork).

## Limits (what "equal" does and does not prove)

- Equal = same normalized instruction stream and same ordered branch/call targets for that function under the stated compiler/flags/headers. It is evidence that the shipping function was built from equivalent source; it is **not** identical source text (comments, dead code and macro-only differences vanish), and it does not cover data: tables (`.rodata`/`.data`), `static` initializers and struct layouts need the separate data compare (`recon-ac107/cmpdata.py` style) or `sensor_compare.py`.
- Different = the host build differs from the image under these conditions. Header generation matters: the same sources changed outcome for 8 functions between 4.9.117 and 4.9.190 headers (759 vs 767 equal). Host headers are not the vendor's build tree (not public); the CI build of the real tree is the authoritative run. Per-directory Kbuild flags are not applied on the host.
- Absent functions (inlined or discarded) are unchecked, not equal.
- The database is derived from the shipping image: hashes, sizes and addresses only. It is small and contains no code, but it is firmware-derived; decide before publishing.
- `--explain` needs the private image; CI receipts carry digests and VAs only.
- The fixture for panels uses stub display headers (`recon/stub-amar`); equal code with stub inline headers is equal code, but a real display core may still change other functions.

## Host rebuild recipe (the temporary trees were deleted)

1. `recon-ac107/tc-darwin/clang/bin/clang-9` (AOSP clang-r353983c darwin build) and `recon-ac107/ktree` (Lenovo 4.9.117 headers + stock-config `autoconf.h`) are the default (`cc.sh`).
2. 4.9.190 header tree: `git archive 0a95b50 include arch/arm64/include arch/arm/include/asm/{opcodes*,xen} drivers/misc/mediatek/include drivers/misc/mediatek/base/power/{include,mt6765} ...` from the philmb clone, `include/generated/{bounds,timeconst,utsrelease}.h`, `uapi` from `ktree`, `autoconf.h` from the kernel's own `scripts/kconfig/conf --silentoldconfig` on the v4-patched Kconfig tree and the stock config; `KTREE=<dir> host_compile.sh SRC_ROOT OUT FILE.c ...`.
3. `python3 object_fidelity.py shipping-function-fingerprints.json.gz receipt.json OBJDIR [--explain Image.raw kallsyms.txt] [--expect expect.json]`.
