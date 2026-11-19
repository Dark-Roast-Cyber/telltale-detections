# Telltale community detections

Community rules, independently labeled synthetic scenarios, and analyst notes
for [Telltale](https://github.com/Dark-Roast-Cyber/telltale). Rules are written
in [Rule v2](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/rule-format.md), Telltale's Sigma profile, one rule per file, with `tdx.`
names, and ship as the Apache-2.0 `telltale.community` rule package. Telltale
embeds a pinned release and enables it by default; Telltale's core rules remain
separate and are reviewed under its own content standard.

## Browse

- [Rules](rules/) and [analyst notes](docs/detections/)
- [MITRE ATLAS coverage](docs/atlas-coverage.md) of Telltale core and community rules
- [Adversarial, benign, and visibility-limited scenarios](scenarios/)
- [Assessment runner](scripts/check.py), [package builder and lint](scripts/community_package.py), and [tests](tests/)
- [Contributing](CONTRIBUTING.md)

## Maturity and releases

| Rule `status` | Released |
| --- | --- |
| `experimental` | No; evaluated by the synthetic assessment |
| `test` | Yes; enabled by default in Telltale |
| `stable` | Yes; eligible for promotion to a Telltale core rule |

`experimental` keeps a rule out of the release package. If an operator loads
it manually, the status does not suppress scoring or alerts. See
[Telltale's rule override instructions](https://github.com/Dark-Roast-Cyber/telltale/blob/main/docs/install.md#community-rules-and-rule-packages)
for local disablement and score tuning.

`main` is the release branch. Pushing a `vX.Y.Z` tag on `main` runs the
[release workflow](.github/workflows/release.yml): contribution lint, tests, the
pinned assessment, a package of every `test` and `stable` rule, validation with
the pinned Telltale, a build-provenance attestation, and a GitHub Release with
`telltale.community-X.Y.Z.package.yaml` and `SHA256SUMS`. Telltale refreshes its
embedded snapshot from a release with `scripts/dev/vendor-community-rules.py`.

## Use a release

Telltale already includes a community snapshot. To run a newer release without a
Telltale upgrade, verify and install the package; it replaces the embedded
snapshot as a whole. Packages in format `telltale-rule-package/v2`, built from
Rule v2 files, need Telltale 0.8.0 or later; Telltale 0.7 reads only the earlier
format v1 packages.

```sh
gh release download v0.1.0 --repo Dark-Roast-Cyber/telltale-detections \
  --pattern '*.package.yaml' --pattern SHA256SUMS
sha256sum --check SHA256SUMS
gh attestation verify telltale.community-0.1.0.package.yaml \
  --repo Dark-Roast-Cyber/telltale-detections
sudo install -D -m 0644 telltale.community-0.1.0.package.yaml \
  /etc/telltale/rule-packages.d/telltale.community.yaml
telltale config validate
```

Use `--no-community-rules` or `TELLTALE_COMMUNITY_RULES=0` to run only Telltale's
core rules.

## Linux assessment

`python3 -m unittest discover -s tests` needs only Python; the tests that load
rules in Telltale run when `TELLTALE_BIN` names a build at the
[`pins.json`](pins.json) revision. The lint reads each rule through that build:
`python3 scripts/community_package.py lint --telltale <binary>`. For the full gate, place
the [lab](https://github.com/Dark-Roast-Cyber/telltale-lab) and Telltale
checkouts beside this repository at the revisions in [`pins.json`](pins.json),
then run:

```sh
bash scripts/linux-check.sh
```

The [entrypoint](scripts/linux-check.sh) builds Telltale, lints contributions,
runs this repository's tests, installs every candidate rule (all maturities) as
the community package in the pinned Telltale, and assesses scenarios in Codex and
OpenCode formats. The pinned revision must read Rule v2 and package format v2. [The runner](scripts/check.py) owns the selected generation profiles;
each summary row records the profile and generator version. Scenario commands
remain data and are never executed.

Set `TELLTALE_BIN` to a binary from the pinned revision to skip the build. The
entrypoint also exposes checkout and target-directory overrides. Its optional
first argument selects an empty report directory; otherwise it creates one under `/tmp`.

Review `summary.json` and the per-case `report.json` files in that directory.
The summary's `rule_maturities` maps each loaded candidate rule ID to
`experimental`, `test`, or `stable`. Look up a row's `observed_rule_ids` in
that map to identify experimental matches, including ones not named in the
scenario expectations. Core rules are not in the map. This annotates the
assessment only; it does not label whole events or change Event 3.

The runner fails on invalid scenarios or rules, missing inputs, Event 3 schema
failures, or a synthetic secret leak. It records `missed`, `false_positive`, and
`not_evaluable` as findings in `summary.json` with `review_required: true`; its
zero exit means the assessment completed, not that detection quality passed.
`candidate_content_present: false` means candidate rules, candidate scenarios,
or both were absent; it is not evidence of candidate coverage.
Labels come from the scenario file and are never rewritten from detector output.

## Related

- [Telltale evidence lab](https://github.com/Dark-Roast-Cyber/telltale-lab): synthetic store generation and independent labels
- [Daybreak scope](https://github.com/Dark-Roast-Cyber/telltale-lab/blob/main/docs/daybreak-adversarial-scope.md): the bounded experiment
- [Agent Archaeology](https://agentarchaeology.ai/): evidence and detection context
