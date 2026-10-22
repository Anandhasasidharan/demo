# Automated Patching — interactive 3D explainer

An interactive walkthrough of an automated vulnerability patching pipeline:
**ingest → prioritise → generate → validate → ship.**

**Live demo:** https://anandhasasidharan.github.io/demo/

**Base paper:** Hore, Shah & Bastian (2023), *Deep VULMAN: A deep reinforcement learning-enabled cyber vulnerability management framework*, Expert Systems with Applications 221:119734.
DOI: [10.1016/j.eswa.2023.119734](https://doi.org/10.1016/j.eswa.2023.119734)

---

## What this demonstrates

Each glowing token is a CVE travelling through a pipeline. Its size reflects severity.
At the **Validate** stage the generated patch is judged against a real oracle: it must
compile, the original exploit must stop working, and the project's tests must still pass.
Failures turn red and fall away — that is review budget spent for nothing. Patches that
pass rise and turn green.

The claim on screen: **once patch generation is automated, the ordering policy determines
how many validated patches you can actually ship per unit of review budget.**

---

## The pipeline in detail — how a patch is actually applied

This is the mechanism the animation abstracts. Each step is a concrete operation, not a metaphor.

### 1 · Intake
- Join the CVE against **NVD** (description, CVSS v3.1 base score, CWE, references).
- Join **EPSS** as of the decision date (never the current score — that leaks the future).
- Join **CISA KEV** membership.
- Attach local context: asset criticality, network exposure, IDS alerts on that host.

Output: a `vuln.json` record — the unit the queue operates on.

### 2 · Localise
- Run the proof-of-concept inside the benchmark container under
  **AddressSanitizer**, so the crash is deterministic and the stack is precise.
- Map the top stack frame to a function and source line.
- Extract that function plus surrounding context as the repair target.

### 3 · Prioritise
Order the queue by expected value per unit of review budget, not by severity alone:

```
EV(c) = P(exploit) × impact(CVSS, asset) × P(patch validates) / cost
```

In practice this is a weighted score over CVSS, EPSS, KEV, asset context and
**patchability** — the term no existing framework uses.

### 4 · Generate
- Build a prompt: vulnerable function + CWE description + 2–5 retrieved similar fixes
  (RAG over CVEfixes / Big-Vul) + build context.
- Sample **k = 3** candidates from an open-weight model (CodeLlama / Qwen2.5-Coder).
- Emit unified diffs, not prose.

### 5 · Validate — the gate (this is the contribution)
Candidates pass through an ordered ladder; the cheapest checks run first.

| # | Check | Fail action | Why it exists |
|---|---|---|---|
| 1 | `git apply` the diff | reject candidate | a patch that does not apply is not a patch |
| 2 | Compile with the project's build system | reject candidate | syntax and type errors |
| 3 | Rebuild with `-fsanitize=address,undefined` | reject candidate | memory-safety context |
| 4 | Replay the original PoC | reject candidate | the exploit must no longer crash |
| 5 | Run the project's regression tests | reject candidate | must not break behaviour |
| 6 | Cheat heuristics (deleted body, hardcoded input, silenced errors, test edits) | reject candidate | prevents gaming the oracle |
| 7 | Static checks (`clang-tidy`, `semgrep`) on changed lines | warn / reject | keeps the fix idiomatic |

Only a candidate that clears every check is **validated**. If all *k* fail, the CVE is
recorded as a failure and escalated to a human — never counted as a success.

### 6 · Ship
Produce a pull request containing the diff, the PoC output before and after, the
sanitizer log and the test report. Deployment is a **reviewable PR**, not an automatic
merge.

---

## The gaps we close from the base paper

| Base paper (Deep VULMAN, 2023) | This work | Evidence |
|---|---|---|
| Output is a **ranked list for humans** | Adds generation and validation — the list becomes patches | base paper §3, Fig. 2 |
| **No notion of patch correctness** | Validation gate with PoC replay + regression tests | new (C2) |
| Reward = importance + resource cost, with no feedback from real fix outcomes | Adds a **patchability** term: what can actually be fixed | new (C3) |
| Assumes the scarce resource is human triage hours | Redefines it as **review bandwidth** — still scarce when generation is cheap | new framing |
| Open loop: list, then stop | Verified patches feed outcomes back into the queue | new (C4) |
| Measures CVEs *selected* | Measures patches **validated and shipped per review-hour** | new metrics |

What the gap analysis in the literature adds: prioritisation research stops at the list;
repair research fixes whatever it is handed; 2026 reviews explicitly call the end-to-end
lifecycle an open problem. Nothing measures validated patches per unit of budget.

---

## What is measured

| Metric | Definition | Why this one |
|---|---|---|
| **VPR** — Validated Patch Rate | passes compile **and** PoC silent **and** regression ÷ attempted | strict conjunction = "could this ship?" |
| **VPB** — Validated Patches per Budget | validated ÷ review-hours | the scarce resource is review time |
| **MTTP** | disclosure → validated patch, days | the motivation is shrinking patch windows |
| **Critical coverage @ T** | share of CVSS ≥ 9.0 validated within T days | operations care about the dangerous tail |
| **Overfit rate** | passes PoC but rejected by cheat checks | guards against gaming the oracle |
| **Cost** | GPU-minutes and USD per valid patch | separates a paper from a demo |

---

## Requirements needed for the paper

| Requirement | Minimum viable | Why it is needed | Status |
|---|---|---|---|
| **Benchmark with real PoCs** | ARVO or Sec-bench, ~300 CVEs | without an oracle, "validated" means nothing | to set up |
| **CVE metadata feeds** | NVD API, EPSS API (as-of date), KEV JSON | the ranking inputs | available, free |
| **GPU for inference** | 1 × 24 GB, or ~$150–400 rented | run a 7B code model at k=3 over 300 CVEs | to arrange |
| **CPU + disk** | 16 cores, ~300 GB | Docker builds per CVE | to arrange |
| **Software stack** | Python 3.11, Docker, vLLM or llama.cpp, XGBoost, PuLP | the build itself | available |
| **Open-weight model** | Qwen2.5-Coder-7B or CodeLlama-7B/13B | reproducibility — pin the revision | available |
| **Compiler toolchain** | clang/gcc with ASan + UBSan | the validation gate | available |
| **Skills** | Python, Docker, git, basic ML (one `fit`/`predict`) | no novel architecture required | — |
| **Time** | ~10 weeks full-time (16–20 part-time) | engineering + experiments + writing | planned |
| **Scopus access** | institutional | literature review and venue checks | available |
| **Human review policy** | every generated patch reviewed before merge | safety and ethics; also defines the budget | policy needed |
| **Evaluation discipline** | 3 seeds, ≥30 episodes, Wilcoxon, paired comparisons | credibility | defined in plan |

**What is *not* required:** a new model architecture, a GPU cluster, RL expertise,
a new dataset, or permission from the base paper's authors.

---

## Scope, stated honestly

**In scope:** open-source C/C++ with a reproducible proof-of-concept and a
function-local repair; memory-safety (CWE-787/125/416/476/190) and injection
(CWE-89/78/79/22) classes.

**Out of scope:** authentication and design flaws, race conditions, kernel,
firmware, closed-source or binary-only targets, multi-file redesigns, and anything
without a reproducible trigger.

Where a vendor has already shipped a fix, upgrading is the correct action. This
pipeline targets the cases where no adequate fix exists in the deployed version, or
where a backport is required.

---

## Guided demo script (90 seconds)

1. **Let it play.** Tokens flow left to right; the caption cycles through the five stages.
2. **Click the amber ring (Validate).** *"This is the part most tools skip. A patch is not real until it compiles, the exploit stops working, and the tests still pass."*
3. **Point at the falling red tokens.** *"These failed validation — and they consumed the same budget as a success."*
4. **Click the violet ring (Prioritise).** *"So the order matters. Ranking by severity alone spends budget on bugs the pipeline cannot fix."*
5. **Click "What this shows".** The research summary: gap, stages, metrics, scope.
6. Close with: *"The paper measures how many validated patches you can ship per hour of review, and whether smart ordering beats ranking by severity."*

---

## Controls

| Input | Action |
|---|---|
| Drag | orbit the camera |
| Scroll | zoom |
| Click a ring | focus a stage and read its explanation |
| Stage list (right) | jump to a stage without hunting for the ring |
| Pause / Reset | freeze the flow, restart the counters |
| "What this shows" | research summary modal |
| Esc | close the modal |

---

## Run locally

No build step — it is one static file.

```bash
python -m http.server 8000
# open http://localhost:8000
```

Opening `index.html` directly also works; Three.js is loaded from a CDN, so an
internet connection is required.

## Structure

```
index.html   # styles, Three.js scene, HUD, research modal
README.md    # this document
```

## Notes

- Three.js r160 via jsDelivr import map; no tracking, no analytics, no external fonts.
- If the CDN is unreachable the page explains the failure instead of showing a blank canvas.
- Deployed with GitHub Pages from `main` (root). Push to `main` and it rebuilds in ~40 s.
