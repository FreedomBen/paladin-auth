<!--
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# `paladin-auth-gtk` Flathub submission

This directory carries the artifacts that make up the Flathub
submission for `paladin-auth-gtk` (docs/DESIGN.md §11.4, docs/IMPLEMENTATION_PLAN_04_GTK.md
§"Milestone 7 checklist" → "File the Flathub submission and inherit
Flatpak signing from Flathub").

| File                              | Purpose                                                                                                  |
| --------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `org.tamx.PaladinAuth.Gui.yml`        | The flatpak-builder manifest Flathub consumes. Filename matches the app-id basename per Flathub convention. |
| `flathub.json`                    | Per-app build options Flathub honors (initial scope: `only-arches: ["x86_64"]`).                          |
| `README.md`                       | This file.                                                                                               |

`packaging/flatpak/paladin-auth-gtk.yml` is the **local** packaging
dry-run (CI builds it via `flatpak-builder` against the workspace
tree with `type: dir, path: ../..`). The Flathub manifest above is
**not** the same file — Flathub's build infra has no access to a
local checkout, so the submission uses an upstream `type: git`
source pointer plus a `cargo-sources.json` companion for vendored
Cargo deps.

## Filing the initial submission

1. Fork <https://github.com/flathub/flathub> on GitHub.
2. Create a branch named `org.tamx.PaladinAuth.Gui` in your fork.
3. Add `org.tamx.PaladinAuth.Gui.yml` and `flathub.json` from this
   directory to the root of that branch (Flathub's "new-submission"
   layout). Verify the files match in-tree byte-for-byte —
   `crates/paladin-auth-gtk/tests/packaging_flathub_submission_logic.rs`
   pins the in-tree shape, so the only correct submission is a
   copy of what landed in this directory.
4. Generate `cargo-sources.json` against the tag the manifest
   pins (see "Per-release source pin" below) and add it to the
   branch.
5. Open a pull request against `flathub/flathub` with the title
   `New app: org.tamx.PaladinAuth.Gui` and link to the GitHub Release
   that matches the manifest's `tag:` / `commit:`.
6. Address Flathub reviewer feedback. The
   `flathub_manifest_finish_args_are_exactly_the_milestone_7_baseline_set`
   contract test exists to keep reviewer-requested sandbox changes
   from landing without a corresponding plan update — if a reviewer
   asks for a portal the test would reject, update
   `docs/IMPLEMENTATION_PLAN_04_GTK.md` §11.4 first.
7. Once the PR merges, Flathub creates
   `flathub/org.tamx.PaladinAuth.Gui` automatically. Subsequent
   releases ship as PRs against that new repo instead of
   `flathub/flathub`.

## Per-release source pin

Each release stamps the manifest's `sources:` block with the new
tag and commit SHA, and regenerates `cargo-sources.json` against
that tag's `Cargo.lock`. The release pipeline runs both steps;
the manual equivalents are:

```sh
# 1. Stamp the tag + commit. Replace v0.2.0 with the release tag.
TAG=v0.2.0
COMMIT=$(git rev-parse "${TAG}")
sed -i "s/tag: v.*/tag: ${TAG}/" packaging/flathub/org.tamx.PaladinAuth.Gui.yml
sed -i "s/# commit: .*/commit: ${COMMIT}/" packaging/flathub/org.tamx.PaladinAuth.Gui.yml

# 2. Regenerate cargo-sources.json against the new tag.
#    flatpak-cargo-generator ships in the flatpak-builder-tools repo:
#    https://github.com/flatpak/flatpak-builder-tools/tree/master/cargo
git fetch --tags origin
git checkout "${TAG}"
flatpak-cargo-generator.py Cargo.lock -o /tmp/cargo-sources.json
```

The release pipeline then opens a PR against
`flathub/org.tamx.PaladinAuth.Gui` with the stamped manifest and the
fresh `cargo-sources.json`.

## Signing inheritance

Per docs/DESIGN.md §11.4 / §11.6 ("Flatpak releases inherit Flathub's
signing"), every build Flathub publishes is signed with Flathub's
own key — so the release pipeline's
`packaging/sign/sign-artifact.sh` is **not** invoked for the
Flatpak output. Downstream users verify Flatpak installs against
Flathub's trust anchor, not against the paladin-auth project's
`packaging/sign/minisign.pub`. The minisign wrapper covers only
the `.deb` / `.rpm` / AppImage artifacts hosted on GitHub Releases.

## Reproducibility

The Flathub builder enforces `--locked --offline --release` cargo
invocations (pinned by
`crates/paladin-auth-gtk/tests/packaging_flathub_submission_logic.rs::flathub_manifest_uses_locked_offline_cargo_build`)
and runs without `--share=network` in the sandbox. Together with
the per-tag `cargo-sources.json` regeneration, that means two
runs of the same tag against the same Flathub build infra produce
identical outputs.
