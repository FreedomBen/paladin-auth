// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase B audit: `Account` must not implement `serde::Serialize`,
// even when the `error-serde` cargo feature is enabled (the feature
// only ever wires Serialize onto the non-secret projection types
// listed in docs/DESIGN.md §4.7 / Phase J). This test is expected to
// fail to compile.

fn requires_serialize<T: serde::Serialize>() {}

fn main() {
    requires_serialize::<paladin_core::Account>();
}
