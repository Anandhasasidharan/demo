# Automated Patching — interactive 3D explainer

A single-page Three.js walkthrough of an automated vulnerability patching pipeline:
**ingest → prioritise → generate → validate → ship.**

Live demo: https://anandhasasidharan.github.io/demo/

## What it shows

Each glowing token is a CVE travelling along a pipeline. Its size reflects severity.
At the validation stage the token is judged: if the generated patch does not survive
compilation, exploit replay and regression tests, it turns red and falls away — that
is review budget spent for nothing. Patches that pass rise and turn green.

The point being demonstrated: **once patching is automated, the ordering decision
determines how many validated patches you can actually ship per unit of review budget.**

## Controls

| Input | Action |
|---|---|
| Drag | orbit the camera |
| Scroll | zoom |
| Click a ring | focus a stage and read its explanation |
| Click a stage in the right rail | same, without needing to find the ring |
| Pause / Reset | freeze the flow, restart the counters |
| "What this shows" | research summary: gap, method, metrics, scope |

## Run locally

No build step. Any static server works:

```bash
python -m http.server 8000
# then open http://localhost:8000
```

Opening `index.html` directly from `file://` also works in Chrome; the Three.js module
is loaded from a CDN, so an internet connection is required.

## Structure

```
index.html      # everything: styles, Three.js scene, HUD, modal
```

## Notes

- Three.js r160 via jsDelivr import map.
- No tracking, no analytics, no external fonts.
- If the CDN is unreachable the page explains the failure instead of showing a blank canvas.
