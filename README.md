# Telltale candidate detections

Provisional Rule v1 packs, independently labeled synthetic scenarios, and analyst
notes for [Telltale](https://github.com/Dark-Roast-Cyber/telltale). Candidate IDs use
`tdx.`; they are not bundled or production-qualified Telltale detections.

## Browse

- [Rule packs](packs/) and [analyst notes](docs/detections/)
- [Adversarial, benign, and visibility-limited scenarios](scenarios/)
- [Assessment runner](scripts/check.py) and [tests](tests/)

## Linux assessment

Place the [lab](https://github.com/Dark-Roast-Cyber/telltale-lab) and Telltale
checkouts beside this repository. Use the revisions required by the
[assessment entrypoint](scripts/linux-check.sh), then run:

```sh
bash scripts/linux-check.sh
```

The [entrypoint](scripts/linux-check.sh) builds Telltale, runs the lab and runner
tests, validates candidate rules, and assesses scenarios in Codex and OpenCode
formats. [The runner](scripts/check.py) owns the selected generation profiles;
each summary row records the profile and generator version. Scenario commands
remain data and are never executed.

Set `TELLTALE_BIN` to a binary from the pinned revision to skip the build. The
entrypoint also exposes checkout and target-directory overrides. Its optional
first argument selects an empty report directory; otherwise it creates one under `/tmp`.

Review `summary.json` and the per-case `report.json` files in that directory.
The runner fails on invalid scenarios or rules, missing inputs, Event 3 schema
failures, or a synthetic secret leak. It records `missed`, `false_positive`, and
`not_evaluable` as findings in `summary.json` with `review_required: true`; its
zero exit means the assessment completed, not that detection quality passed.
`candidate_content_present: false` means a candidate rule pack, candidate scenarios,
or both were absent; it is not evidence of candidate coverage.
Labels come from the scenario file and are never rewritten from detector output.

## Related

- [Telltale evidence lab](https://github.com/Dark-Roast-Cyber/telltale-lab): synthetic store generation and independent labels
- [Daybreak scope](https://github.com/Dark-Roast-Cyber/telltale-lab/blob/main/docs/daybreak-adversarial-scope.md): the bounded experiment
- [Agent Archaeology](https://agentarchaeology.ai/): evidence and detection context
