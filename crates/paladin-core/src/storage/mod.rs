// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Vault storage (DESIGN.md §4.3).
//
// Phase E lands the in-memory `VaultPayload` and the bincode v2 codec
// pinned by §4.3 (little-endian, fixed-int, 16 MiB cap, full-input
// consumption). Filesystem I/O — atomic writes, permissions, backup
// rotation, header parsing — lands in subsequent commits.

pub mod payload;

pub use payload::VaultSettings;
// Re-exported for use by upcoming Phase E filesystem code (Store, open,
// create_force, atomic-write pipeline). The codec itself lives in
// `payload`; callers within the crate go through these aliases.
#[allow(unused_imports)]
pub(crate) use payload::{decode_vault_payload, encode_vault_payload, VaultPayload};
