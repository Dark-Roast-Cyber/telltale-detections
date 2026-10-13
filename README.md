# Telltale candidate detections

This repository holds provisional Rule v1 packs, their independently labeled
synthetic scenarios, and analyst notes. Daybreak's scope is in the sibling
`telltale-lab/docs/daybreak-adversarial-scope.md`. Candidate IDs use `tdx.`;
they are not bundled Telltale detections.

Expected content:

```text
packs/experimental/<name>.yaml
scenarios/adversarial/<id>.json
scenarios/benign/<id>.json
scenarios/visibility-limited/<id>.json
docs/detections/<id>.md
```

Run the Linux gate from this repository after placing the lab and Telltale
checkouts beside it:

```sh
bash scripts/linux-check.sh
```

The script requires Telltale source at `2e8c56a`, builds its CLI with Cargo's
target directory under `/tmp`, runs the lab and runner tests, validates every
candidate rule, and analyzes every scenario in both Codex and OpenCode formats.
The assessment explicitly selects the OpenCode `upstream` profile: v2.0.27
`session_v2`/`session_message` history, rather than legacy `message`/`part`
tables. Codex uses the `compatible` profile. Each summary row records the
selected profile and generator version. At Telltale `2e8c56a`, OpenCode v2
produces `not_evaluable` with reason `no_records_acquired`; the gate retains
that acquisition gap as a finding. Legacy generator tests remain compatibility
checks and do not determine the profile used for scenario assessments.
It uses only the lab's `scenarios` and `analyze` commands. Scenario commands
remain text inside generated session stores and are never executed.

Set `TELLTALE_BIN` to a previously built binary to skip the build. Set
`TELLTALE_LAB_ROOT`, `TELLTALE_SOURCE`, or `TELLTALE_TARGET_DIR` if the sibling
layout or target directory differs. Pass an optional empty report directory as
the first argument; otherwise the script creates one under `/tmp`.

Review `summary.json` and the per-case `report.json` files in that directory.
The runner fails on invalid scenarios or rules, missing inputs, Event 3 schema
failures, or a synthetic secret leak. It records `missed`, `false_positive`, and
`not_evaluable` as findings in `summary.json` with `review_required: true`; its
zero exit means the assessment completed, not that detection quality passed.
`candidate_content_present: false` means only the lab baseline was exercised.
Labels come from the scenario file and are never rewritten from detector output.

This is the local Linux CI entrypoint. A hosted workflow needs immutable refs
for the lab and detections repositories after their first reviewed commits and
publication. No remote or commit is required for the local gate.
