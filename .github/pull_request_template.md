## Summary

<!-- Behavior detected or changed, and why it matters for agent sessions. -->

## Checklist

- [ ] Rule IDs use `tdx.` and each rule's `status` matches its `packs/<maturity>/` directory
- [ ] Adversarial scenario that must match and benign look-alike that must not match
- [ ] Analyst note at `docs/detections/<rule-id>.md`, including false positives and gaps
- [ ] Synthetic data only: fabricated secrets, reserved hosts, no real sessions
- [ ] Labels were written from the scenario facts, not from detector output
- [ ] `python3 scripts/community_package.py lint` and `python3 -m unittest discover -s tests` pass
- [ ] Commits are signed off (`git commit -s`)

## Assessment

<!-- For a maturity change, paste the relevant summary.json rows: status per format and any not_evaluable reasons. -->
