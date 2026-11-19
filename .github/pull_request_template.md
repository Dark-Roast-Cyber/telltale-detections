## Summary

<!-- Behavior detected or changed, and why it matters for agent sessions. -->

## Checklist

- [ ] Rule v2 files at `rules/<name>.yml` with `tdx.` names, a UUIDv4 `id`, and `status` set
- [ ] Adversarial scenario that must match and benign look-alike that must not match
- [ ] Analyst note at `docs/detections/<name>.md`, with false positives, category-level coverage limits, and changes
- [ ] Synthetic data only: fabricated secrets, reserved hosts, no real sessions
- [ ] Labels were written from the scenario facts, not from detector output
- [ ] `python3 scripts/community_package.py lint --telltale <binary>` and `python3 -m unittest discover -s tests` pass
- [ ] Commits are signed off (`git commit -s`)

## Assessment

<!-- For a maturity change, paste the relevant summary.json rows: status per format and any not_evaluable reasons. -->
