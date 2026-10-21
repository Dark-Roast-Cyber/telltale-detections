# Telltale community detections

Community Rule v1 packs, independently labeled synthetic scenarios, and analyst
notes for [Telltale](https://github.com/Dark-Roast-Cyber/telltale). Rules use
`tdx.` IDs and ship as the Apache-2.0 `telltale.community` rule package. Telltale
embeds a pinned release and enables it by default; Telltale's core rules remain
separate and are reviewed under its own content standard.

## Browse

- [Rule packs](packs/) and [analyst notes](docs/detections/)
- [Adversarial, benign, and visibility-limited scenarios](scenarios/)
- [Assessment runner](scripts/check.py), [package builder and lint](scripts/community_package.py), and [tests](tests/)
- [Contributing](CONTRIBUTING.md)

## Maturity and releases

| Directory | Rule `status` | Released |
| --- | --- | --- |
| `packs/experimental/` | `experimental` | No; assessed in CI only |
| `packs/test/` | `test` | Yes; enabled by default in Telltale |
| `packs/stable/` | `stable` | Yes; eligible for promotion to a Telltale core rule |

`main` is the release branch. Pushing a `vX.Y.Z` tag on `main` runs the
[release workflow](.github/workflows/release.yml): contribution lint, tests, the
pinned assessment, a package of every `test` and `stable` pack, validation with
the pinned Telltale, a build-provenance attestation, and a GitHub Release with
`telltale.community-X.Y.Z.package.yaml` and `SHA256SUMS`. Telltale refreshes its
embedded snapshot from a release with `scripts/dev/vendor-community-rules.py`.

## Use a release

Telltale already includes a community snapshot. To run a newer release without a
Telltale upgrade, verify and install the package; it replaces the embedded
snapshot as a whole:

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

`python3 scripts/community_package.py lint` and
`python3 -m unittest discover -s tests` need only Python. For the full gate, place
the [lab](https://github.com/Dark-Roast-Cyber/telltale-lab) and Telltale
checkouts beside this repository at the revisions in [`pins.json`](pins.json),
then run:

```sh
bash scripts/linux-check.sh
```

The [entrypoint](scripts/linux-check.sh) builds Telltale, lints contributions,
runs this repository's tests, installs every candidate pack (all maturities) as
the community package in the pinned Telltale, and assesses scenarios in Codex and
OpenCode formats. The pinned revision must support rule packages. [The runner](scripts/check.py) owns the selected generation profiles;
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
