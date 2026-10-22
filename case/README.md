# Case study — CVE-2022-40674 (libexpat)

A reproducible worked example of the validation gate: a real use-after-free,
reproduced against the real vulnerable release, fixed with the real upstream patch,
and verified before and after.

| Build | Result | Exit code |
|---|---|---|
| libexpat 2.4.8 (vulnerable) | access violation on the resuming parse | `0xC0000005` |
| 2.4.8 + `patch.diff` | completes, no fault | `0` |
| libexpat 2.4.9 (fixed release) | completes, no fault | `0` |

## What triggers it

An internal entity whose replacement text contains a comment, a comment handler that
suspends the parser, and a resume. On resume `internalEntityProcessor` returns the
result of `doContent()` without calling `storeRawNames()`, so the parser later walks
over the entity text buffer that was freed during the suspend — CWE-416.

The input is 2,115 bytes and the split is identical to the upstream regression test
(`expat/tests/runtests.c`, commit `a7ce80a0`).

## Run it

### Windows (guard-page allocator)

```powershell
cd case
powershell -ExecutionPolicy Bypass -File build.ps1
```

### Linux / macOS (AddressSanitizer)

```bash
cd case
./build.sh
```

Both scripts clone libexpat, compile three builds (vulnerable, vulnerable + patch,
fixed release), and run the same input through each. Expect under a minute after
the clone.

## Files

| File | Purpose |
|---|---|
| `driver.c` | the harness: builds the trigger, injects the allocator, parses in three steps |
| `patch.diff` | the upstream fix, applies cleanly to 2.4.8 |
| `expat_config.h` | minimal build configuration, because the source tree is extracted with `git archive` rather than configured |
| `build.ps1` / `build.sh` | clone, build, run, compare |
| `evidence/*.txt` | captured output of the three runs |

## Which allocation oracle, and why

AddressSanitizer is not available for this Windows toolchain, so `driver.c` installs a
guard-page allocator through expat's `XML_ParserCreate_MM` hook: every block is placed
so that it ends at a page boundary followed by a `PAGE_NOACCESS` page, and every freed
block is itself switched to `PAGE_NOACCESS` and kept reserved. A use-after-free
therefore faults at the exact instruction that touches freed memory, which is why the
run stops between `step 2` and `step 3`.

On Linux and macOS the default allocator is used and ASan provides the same guarantee.

## Honesty boundary

The patch shown is the **upstream fix**, used as the reference for a correct repair.
The language-model generator was **not** run here: this machine has no GPU, and a
fabricated transcript would be worse than no transcript. What is real is everything
usually hand-waved — the vulnerable source, the trigger, the fault, the repair, and
the before/after evidence.

What this case proves: the gate can distinguish a broken build from a fixed one on a
real vulnerability, with evidence a reviewer can rerun.
What it does not prove: anything about the generator's average success rate, or about
CVEs outside this class.
