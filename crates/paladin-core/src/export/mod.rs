// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Export surface (DESIGN.md §4.6 / §4.7).
//
// Two formats are supported:
//   - [`otpauth_list`] — infallible JSON array of canonical
//     `otpauth://` URIs, suitable for piping into another
//     authenticator that consumes the otpauth scheme.
//   - `encrypted` — an encrypted Paladin bundle (see
//     `crate::export::encrypted`, Phase I.9).
//
// Front-end CLI / TUI / GUI export commands write the resulting bytes
// through [`crate::write_secret_file_atomic`] for the §4.3 atomic-write
// guarantees.

mod otpauth_list;

pub use otpauth_list::otpauth_list;
