// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pre-/post-AEAD plaintext zeroization witness (DESIGN.md §4.4 /
// Phase F.14).
//
// `crypto::buffer::ZeroizingBytes` invokes [`observe`] from inside its
// `Drop` impl *after* it has zeroized the backing bytes but *before*
// the underlying `Vec<u8>` deallocates. The witness records what it
// saw (site, length at observation time, capacity, and whether every
// observed byte was zero) into a thread-local queue that tests drain
// via [`take_observations`].
//
// Witness recording is compiled in only under `cfg(test)` (so unit
// tests pick it up automatically) or behind the `test-zeroize-witness`
// cargo feature (so integration tests opt in explicitly). Production
// builds keep the no-op `observe` stub that compiles away.
//
// The wrapper passes a safe `&[u8]` borrow rather than a raw pointer
// (the crate is `#![forbid(unsafe_code)]`); equivalent for the
// "zeroized before deallocation" assertion the design calls for, since
// the borrow is taken between the in-place zeroize and the auto-drop
// of the inner `Vec<u8>`.

/// Where in the AEAD pipeline a zeroization observation came from.
///
/// Always defined so the `ZeroizingBytes` wrapper can carry one in
/// every build, even when witness recording is compiled out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessSite {
    /// The bincode-serialized `VaultPayload` buffer fed into AEAD encrypt.
    EncryptPreAead,
    /// The plaintext buffer returned by AEAD decrypt before / after
    /// `decode_vault_payload` consumes it.
    DecryptPostAead,
    /// The 32-byte AEAD key cached on `Vault` (Phase H). Observed
    /// from inside `EncryptedCache`'s key-buffer drop after the
    /// in-place zeroize but before the inline storage is reused.
    EncryptedCacheKeyDrop,
    /// The retained passphrase bytes cached on `Vault` (Phase H).
    /// Observed from inside `EncryptedCache`'s passphrase-buffer drop
    /// after the in-place zeroize but before the heap allocation
    /// is freed.
    EncryptedCachePassphraseDrop,
}

#[cfg(any(test, feature = "test-zeroize-witness"))]
mod active {
    use super::WitnessSite;
    use std::cell::RefCell;

    /// One zeroization observation captured during a `ZeroizingBytes::drop`.
    #[derive(Clone, Debug)]
    pub struct Observation {
        /// Where in the pipeline the buffer was held.
        pub site: WitnessSite,
        /// Length of the observed slice at the moment the witness ran
        /// (matches the buffer's `Vec::len` because the wrapper does
        /// an in-place zeroize that preserves length).
        pub original_len: usize,
        /// `Vec::capacity` at observation time (unchanged by zeroize).
        pub capacity: usize,
        /// `true` iff every byte in the observed slice read as zero
        /// (i.e. the in-place zeroize ran).
        pub all_zero: bool,
    }

    thread_local! {
        static OBS: RefCell<Vec<Observation>> = const { RefCell::new(Vec::new()) };
    }

    /// Drop any observations queued on this thread without inspecting them.
    pub fn clear_observations() {
        OBS.with(|o| o.borrow_mut().clear());
    }

    /// Take + clear the observations queued on this thread.
    pub fn take_observations() -> Vec<Observation> {
        OBS.with(|o| std::mem::take(&mut *o.borrow_mut()))
    }

    pub(crate) fn observe(site: WitnessSite, slice: &[u8], capacity: usize) {
        let all_zero = slice.iter().all(|&b| b == 0);
        OBS.with(|o| {
            o.borrow_mut().push(Observation {
                site,
                original_len: slice.len(),
                capacity,
                all_zero,
            });
        });
    }
}

#[cfg(any(test, feature = "test-zeroize-witness"))]
pub use active::{clear_observations, take_observations, Observation};

#[cfg(any(test, feature = "test-zeroize-witness"))]
pub(crate) use active::observe;

#[cfg(not(any(test, feature = "test-zeroize-witness")))]
#[inline(always)]
pub(crate) fn observe(_site: WitnessSite, _slice: &[u8], _capacity: usize) {}
