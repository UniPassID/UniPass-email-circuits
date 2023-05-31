use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField, ToBytes};
use ark_std::Zero;
use sha3::{Digest, Keccak256};
pub struct TranscriptLibrary {
    //uint256 constant FR_MASK = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    //here just represent the highest byte 0x1f
    pub FR_MASK: u8,
    pub DST_0: [u8; 4],
    pub DST_1: [u8; 4],
    pub DST_CHALLENGE: [u8; 4],

    pub state_0: [u8; 32],
    pub state_1: [u8; 32],
    pub challenge_counter: u32,
}

impl TranscriptLibrary {
    pub fn new() -> Self {
        TranscriptLibrary {
            FR_MASK: 0x1f,
            DST_0: [0u8; 4],
            DST_1: [0u8, 0u8, 0u8, 1u8],
            DST_CHALLENGE: [0u8, 0u8, 0u8, 2u8],
            state_0: [0u8; 32],
            state_1: [0u8; 32],
            challenge_counter: 0,
        }
    }

    pub fn update_with_u256(&mut self, value: impl AsRef<[u8]>) {
        let old_state_0: [u8; 32] = self.state_0;

        let mut hasher = Keccak256::new();
        hasher.update(self.DST_0);
        hasher.update(old_state_0);
        hasher.update(self.state_1);
        hasher.update(&value);
        self.state_0 = <[u8; 32]>::from(hasher.finalize_reset());

        hasher.update(self.DST_1);
        hasher.update(old_state_0);
        hasher.update(self.state_1);
        hasher.update(&value);
        self.state_1 = <[u8; 32]>::from(hasher.finalize_reset());
    }

    pub fn update_with_fr<F: PrimeField>(&mut self, fr: &F) {
        let mut value = [0u8; 32];

        let _ = fr.into_repr().to_bytes_be().write(value.as_mut());
        self.update_with_u256(value);
    }

    pub fn update_with_g1<E: PairingEngine>(&mut self, g: &E::G1Affine) {
        let mut bytes = [0u8; 64];

        let _ = g.write(bytes.as_mut());
        let mut x = [0u8; 32];
        for j in 0..32 {
            x[32 - j - 1] = bytes[j];
        }

        self.update_with_u256(x);
        let mut y = [0u8; 32];
        for j in 32..64 {
            y[64 - j - 1] = bytes[j];
        }
        if g.is_zero() {
            // adapt contract
            self.update_with_u256(x);
        } else {
            self.update_with_u256(y);
        }
    }

    fn change_u32_to_bytes(&value: &u32) -> [u8; 4] {
        let musk = 0x000f_u32;
        let mut res = [0u8; 4];
        let mut val = value;
        for i in 0..4 {
            res[4 - i - 1] = (val & musk) as u8;
            val >>= 8;
        }
        res
    }

    pub fn generate_challenge<F: PrimeField>(&mut self) -> F {
        let mut hasher = Keccak256::new();
        hasher.update(self.DST_CHALLENGE);
        hasher.update(self.state_0);
        hasher.update(self.state_1);
        let cc = TranscriptLibrary::change_u32_to_bytes(&self.challenge_counter);
        hasher.update(cc);
        let mut query = <[u8; 32]>::from(hasher.finalize_reset());

        self.challenge_counter += 1;
        query[0] &= self.FR_MASK;
        F::from_be_bytes_mod_order(&query)
    }
}
