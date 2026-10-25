//! The IDs the operator's flow accepts (`docs/design.md` section 12). A
//! `job_id` is 26 lower-case base32 characters in the ULID alphabet. A
//! `gate_id` is 16 hex characters. Both derive from the 16-byte gate ID of
//! chaperone, and `job_id` decodes back to it.

/// The ULID alphabet, lower case. It leaves out `i`, `l`, `o` and `u`.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// The length of a `job_id`: 130 bits of base32 hold 128 bits.
pub const JOB_LEN: usize = 26;

/// The bytes of `gate_id`: the first half of the gate.
const GATE_PREFIX: usize = 8;

/// The gate of chaperone, as 16 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate(pub [u8; 16]);

impl Gate {
    /// Read the 32 hex characters chaperone sends.
    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = hex::decode(text).ok()?;
        let bytes: [u8; 16] = bytes.try_into().ok()?;
        Some(Self(bytes))
    }

    /// The `job_id` the flow accepts.
    pub fn job_id(self) -> String {
        let value = u128::from_be_bytes(self.0);
        (0..JOB_LEN)
            .rev()
            .map(|i| {
                let index = usize::try_from((value >> (5 * i)) & 31).unwrap_or(0);
                char::from(ALPHABET[index])
            })
            .collect()
    }

    /// The `gate_id` the flow accepts.
    pub fn gate_id(self) -> String {
        hex::encode(&self.0[..GATE_PREFIX])
    }

    /// Read a `job_id` back. `None` for text that is not one.
    pub fn from_job_id(text: &str) -> Option<Self> {
        if text.len() != JOB_LEN {
            return None;
        }
        let mut value: u128 = 0;
        for (i, byte) in text.bytes().enumerate() {
            let index = ALPHABET.iter().position(|c| *c == byte)?;
            // The first character holds only the top 3 bits.
            if i == 0 && index > 7 {
                return None;
            }
            value = (value << 5) | index as u128;
        }
        Some(Self(value.to_be_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gate_round_trips_through_its_job_id() {
        let gate = Gate([
            0xff, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66,
        ]);
        let job = gate.job_id();
        assert_eq!(job.len(), JOB_LEN);
        assert!(job.bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(Gate::from_job_id(&job), Some(gate));
        assert_eq!(gate.gate_id(), "ff00123456789abc");
        assert_eq!(Gate::from_hex(&hex::encode(gate.0)), Some(gate));
    }

    #[test]
    fn the_zero_and_the_full_gate_round_trip() {
        for gate in [Gate([0; 16]), Gate([0xff; 16])] {
            assert_eq!(Gate::from_job_id(&gate.job_id()), Some(gate));
        }
        assert_eq!(Gate([0; 16]).job_id(), "0".repeat(JOB_LEN));
    }

    #[test]
    fn text_that_is_not_a_job_id_is_refused() {
        assert!(Gate::from_job_id("").is_none());
        assert!(Gate::from_job_id(&"0".repeat(25)).is_none());
        assert!(Gate::from_job_id(&"i".repeat(26)).is_none());
        assert!(Gate::from_job_id(&"8".repeat(26)).is_none());
        assert!(Gate::from_hex("abc").is_none());
    }
}
