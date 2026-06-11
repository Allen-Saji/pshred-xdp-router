#![no_std]
//! pshred wire format, shared between the XDP program (`no_std`) and the
//! userspace loader.
//!
//! # Spec source
//! Solana Constellation white paper v0.9, Definition 3 (pshred):
//!
//! ```text
//! (e, c, j, t, i, h, rt, (d_i, pi_i), sigma_t)
//! ```
//!
//! | sym     | field          | this crate            |
//! |---------|----------------|-----------------------|
//! | e       | epoch          | `epoch: u64`          |
//! | c       | cycle          | `cycle: u64`          |
//! | j       | proposer index | `proposer_index: u16` |
//! | t       | pslice index   | `pslice_index: u64`   |
//! | i       | shred index    | `shred_index: u32`    |
//! | h       | tx commitment  | `commitment: [u8;32]` |
//! | rt      | Merkle root    | `merkle_root: [u8;32]`|
//! | sigma_t | Ed25519 sig    | `signature: [u8;64]`  |
//!
//! # Deliberate deviations from the white paper
//!
//! 1. **Field order.** Definition 3 lists the tuple as `..., rt, (d_i, pi_i),
//!    sigma_t`, i.e. the signature comes *after* the variable-length erasure
//!    tail. We serialise `sigma_t` *before* the tail so the entire fixed
//!    header is one contiguous, fixed-offset block. The XDP fast path can then
//!    read any demux field at a constant offset without walking the tail. The
//!    paper gives a tuple, not a byte layout, so this is a serialisation
//!    choice, not a protocol change.
//!
//! 2. **Cycle / pslice widths.** The paper derives the cycle index by dividing
//!    a 64-bit nanosecond Unix timestamp by 50,000,000 (section 3.2), so a
//!    real cycle is ~3.5e10 today, far past `u32::MAX`. The pslice index `t`
//!    is a *global, monotonic* index bound by Eq. (1) `(c-1)mu < t <= c*mu`,
//!    so `t ~= c*mu ~= 1.4e11`. Both must be `u64`. (An earlier draft used
//!    `u32`/`u16` and could only represent toy values.)
//!
//! 3. **Endianness.** The wire is little-endian (matches Solana / bincode).
//!    The kernel reads fields by explicit `from_le_bytes` over bounded byte
//!    slices, so it is alignment-safe regardless of where the header lands in
//!    the packet.

/// White paper p ~= 16: number of concurrent proposers. proposer index `j` is
/// 1-indexed, `1 <= j <= MAX_PROPOSERS`.
pub const MAX_PROPOSERS: u16 = 16;

/// White paper mu ~= 4: max pslices a proposer emits per cycle.
pub const MU: u64 = 4;

/// White paper Gamma_p = q ~= 256: pshreds per pslice / number of attesters.
pub const GAMMA_P: u32 = 256;

/// Well-known UDP destination port for pshred traffic (lab convention).
pub const PSHRED_UDP_PORT: u16 = 9000;

// --- Little-endian byte offsets within the UDP payload (packed) ---
pub const OFF_EPOCH: usize = 0; // u64
pub const OFF_CYCLE: usize = 8; // u64
pub const OFF_PROPOSER: usize = 16; // u16
pub const OFF_PSLICE: usize = 18; // u64
pub const OFF_SHRED_IDX: usize = 26; // u32
pub const OFF_COMMITMENT: usize = 30; // [u8; 32]
pub const OFF_MERKLE: usize = 62; // [u8; 32]
pub const OFF_SIG: usize = 94; // [u8; 64]

/// Total length of the fixed header (epoch .. signature), in bytes.
pub const PSHRED_FIXED_LEN: usize = OFF_SIG + 64; // 158

/// Indices into the `STATS` per-CPU array, shared by the kernel program and the
/// userspace reader so they can never drift apart.
pub mod stats {
    pub const TOTAL: u32 = 0; // pshred-port packets seen
    pub const REDIRECTED: u32 = 1; // handed to an AF_XDP socket
    pub const EQ1_DROP: u32 = 2; // Equation (1) violations dropped
    pub const RANGE_DROP: u32 = 3; // proposer index out of [1, p]
    pub const NO_SOCKET: u32 = 4; // valid pshred but no socket bound -> passed
    pub const COUNT: u32 = 5;
    pub const NAMES: [&str; COUNT as usize] =
        ["total", "redirected", "eq1_drop", "range_drop", "no_socket"];
}

/// Validate Equation (1) from the white paper: `(c - 1) * mu < t <= c * mu`.
///
/// `t` is the *global* pslice index; for a given cycle `c` it falls in the
/// half-open window `((c-1)*mu, c*mu]`. `saturating_*` keeps the bounds sane at
/// the `u64` extremes.
#[inline]
pub fn validate_cycle_bounds(cycle: u64, pslice_index: u64) -> bool {
    let lo = cycle.saturating_sub(1).saturating_mul(MU);
    let hi = cycle.saturating_mul(MU);
    pslice_index > lo && pslice_index <= hi
}

/// Logical view of the fixed header. Not `repr(C)`: it exists for the userspace
/// sender (encode) and tests (round-trip). The kernel parses by raw offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PshredHeader {
    pub epoch: u64,
    pub cycle: u64,
    pub proposer_index: u16,
    pub pslice_index: u64,
    pub shred_index: u32,
    pub commitment: [u8; 32],
    pub merkle_root: [u8; 32],
    pub signature: [u8; 64],
}

impl PshredHeader {
    /// Serialise the fixed header to its little-endian wire form.
    pub fn encode(&self) -> [u8; PSHRED_FIXED_LEN] {
        let mut b = [0u8; PSHRED_FIXED_LEN];
        b[OFF_EPOCH..OFF_EPOCH + 8].copy_from_slice(&self.epoch.to_le_bytes());
        b[OFF_CYCLE..OFF_CYCLE + 8].copy_from_slice(&self.cycle.to_le_bytes());
        b[OFF_PROPOSER..OFF_PROPOSER + 2].copy_from_slice(&self.proposer_index.to_le_bytes());
        b[OFF_PSLICE..OFF_PSLICE + 8].copy_from_slice(&self.pslice_index.to_le_bytes());
        b[OFF_SHRED_IDX..OFF_SHRED_IDX + 4].copy_from_slice(&self.shred_index.to_le_bytes());
        b[OFF_COMMITMENT..OFF_COMMITMENT + 32].copy_from_slice(&self.commitment);
        b[OFF_MERKLE..OFF_MERKLE + 32].copy_from_slice(&self.merkle_root);
        b[OFF_SIG..OFF_SIG + 64].copy_from_slice(&self.signature);
        b
    }

    /// Parse the fixed header from a little-endian payload. Returns `None` if
    /// the slice is shorter than the fixed header.
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < PSHRED_FIXED_LEN {
            return None;
        }
        let r8 = |o: usize| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&payload[o..o + 8]);
            u64::from_le_bytes(a)
        };
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&payload[OFF_COMMITMENT..OFF_COMMITMENT + 32]);
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&payload[OFF_MERKLE..OFF_MERKLE + 32]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&payload[OFF_SIG..OFF_SIG + 64]);
        let mut p = [0u8; 2];
        p.copy_from_slice(&payload[OFF_PROPOSER..OFF_PROPOSER + 2]);
        let mut s = [0u8; 4];
        s.copy_from_slice(&payload[OFF_SHRED_IDX..OFF_SHRED_IDX + 4]);
        Some(PshredHeader {
            epoch: r8(OFF_EPOCH),
            cycle: r8(OFF_CYCLE),
            proposer_index: u16::from_le_bytes(p),
            pslice_index: r8(OFF_PSLICE),
            shred_index: u32::from_le_bytes(s),
            commitment,
            merkle_root,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_len_is_158() {
        assert_eq!(PSHRED_FIXED_LEN, 158);
        // offsets are contiguous and non-overlapping
        assert_eq!(OFF_CYCLE, OFF_EPOCH + 8);
        assert_eq!(OFF_PROPOSER, OFF_CYCLE + 8);
        assert_eq!(OFF_PSLICE, OFF_PROPOSER + 2);
        assert_eq!(OFF_SHRED_IDX, OFF_PSLICE + 8);
        assert_eq!(OFF_COMMITMENT, OFF_SHRED_IDX + 4);
        assert_eq!(OFF_MERKLE, OFF_COMMITMENT + 32);
        assert_eq!(OFF_SIG, OFF_MERKLE + 32);
    }

    #[test]
    fn eq1_toy_values() {
        assert!(validate_cycle_bounds(1, 1));
        assert!(validate_cycle_bounds(1, 4));
        assert!(!validate_cycle_bounds(1, 0));
        assert!(!validate_cycle_bounds(1, 5));
        assert!(validate_cycle_bounds(2, 5));
        assert!(validate_cycle_bounds(2, 8));
        assert!(!validate_cycle_bounds(2, 4));
    }

    #[test]
    fn eq1_realistic_values() {
        // A real cycle ~ unix_nanos / 5e7. Use a mid-2026 value.
        let c: u64 = 1_780_000_000_000_000_000 / 50_000_000; // ~3.56e10
        assert!(c > u32::MAX as u64, "cycle must not fit in u32");
        // valid window is ((c-1)*4, c*4]
        assert!(validate_cycle_bounds(c, c * MU)); // upper bound inclusive
        assert!(validate_cycle_bounds(c, (c - 1) * MU + 1)); // lower bound exclusive +1
        assert!(!validate_cycle_bounds(c, (c - 1) * MU)); // lower bound itself: invalid
        assert!(!validate_cycle_bounds(c, c * MU + 1)); // past upper bound
        let t = c * MU;
        assert!(
            t > u32::MAX as u64,
            "pslice index must not fit in u32 either"
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let h = PshredHeader {
            epoch: 731,
            cycle: 35_600_000_000,
            proposer_index: 7,
            pslice_index: 35_600_000_000 * MU,
            shred_index: 42,
            commitment: [0xAB; 32],
            merkle_root: [0xCD; 32],
            signature: [0xEF; 64],
        };
        let bytes = h.encode();
        assert_eq!(bytes.len(), PSHRED_FIXED_LEN);
        let back = PshredHeader::decode(&bytes).unwrap();
        assert_eq!(h, back);
        assert!(validate_cycle_bounds(back.cycle, back.pslice_index));
    }

    #[test]
    fn decode_rejects_short() {
        assert!(PshredHeader::decode(&[0u8; PSHRED_FIXED_LEN - 1]).is_none());
    }
}
