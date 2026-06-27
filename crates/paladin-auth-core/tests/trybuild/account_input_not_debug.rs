// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase B audit: `AccountInput` must not implement `std::fmt::Debug`.
// This test is expected to fail to compile.

fn requires_debug<T: std::fmt::Debug>() {}

fn main() {
    requires_debug::<paladin_auth_core::AccountInput>();
}
