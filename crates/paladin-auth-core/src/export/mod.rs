// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Export surface (docs/DESIGN.md §4.6 / §4.7).
//
// Two formats are supported:
//   - [`otpauth_list`] — infallible newline-separated list of
//     canonical `otpauth://` URIs (one per line, trailing newline),
//     matching Gnome Authenticator's "Backup → Save in plain text"
//     format. Suitable for piping into any authenticator that
//     consumes the otpauth scheme.
//   - `encrypted` — an encrypted Paladin Auth bundle (see
//     `crate::export::encrypted`, Phase I.9).
//
// Front-end CLI / TUI / GUI export commands write the resulting bytes
// through [`crate::write_secret_file_atomic`] for the §4.3 atomic-write
// guarantees.
//
// A third format — per-account QR — lives in [`qr`] and is consumed
// directly by the front-end QR modals (PNG/SVG file save plus an
// in-place ANSI preview).

mod encrypted;
mod otpauth_list;
mod qr;

pub use encrypted::encrypted;
pub use otpauth_list::otpauth_list;
pub use qr::{qr_ansi, qr_png, qr_svg, QrRenderOptions};
