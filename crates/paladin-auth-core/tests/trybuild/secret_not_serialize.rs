// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase B audit: `Secret` must not implement `serde::Serialize`,
// even when the `error-serde` cargo feature is enabled. This test
// is expected to fail to compile.

fn requires_serialize<T: serde::Serialize>() {}

fn main() {
    requires_serialize::<paladin_auth_core::Secret>();
}
