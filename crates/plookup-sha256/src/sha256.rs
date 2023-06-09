use ark_ff::BigInteger;
use num_bigint::BigUint;

use crate::composer::{Table, Variable};
use crate::{Composer, Error, Field, Map};

pub const INIT_SHA256HASH: &[&str] = &[
    "6a09e667", "bb67ae85", "3c6ef372", "a54ff53a", "510e527f", "9b05688c", "1f83d9ab", "5be0cd19",
];

pub const SHA256CONSTS: &[&str] = &[
    "428a2f98", "71374491", "b5c0fbcf", "e9b5dba5", "3956c25b", "59f111f1", "923f82a4", "ab1c5ed5",
    "d807aa98", "12835b01", "243185be", "550c7dc3", "72be5d74", "80deb1fe", "9bdc06a7", "c19bf174",
    "e49b69c1", "efbe4786", "0fc19dc6", "240ca1cc", "2de92c6f", "4a7484aa", "5cb0a9dc", "76f988da",
    "983e5152", "a831c66d", "b00327c8", "bf597fc7", "c6e00bf3", "d5a79147", "06ca6351", "14292967",
    "27b70a85", "2e1b2138", "4d2c6dfc", "53380d13", "650a7354", "766a0abb", "81c2c92e", "92722c85",
    "a2bfe8a1", "a81a664b", "c24b8b70", "c76c51a3", "d192e819", "d6990624", "f40e3585", "106aa070",
    "19a4c116", "1e376c08", "2748774c", "34b0bcb5", "391c0cb3", "4ed8aa4a", "5b9cca4f", "682e6ff3",
    "748f82ee", "78a5636f", "84c87814", "8cc70208", "90befffa", "a4506ceb", "bef9a3f7", "c67178f2",
];

fn key_to_spread(key: usize, bits: usize) -> u64 {
    let mut key_spread = 0u64;

    let mut tmp = key;
    for i in 0..bits {
        if tmp == 0 {
            break;
        }

        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            key_spread += 1 << (2 * i);
        }
    }
    key_spread
}

impl<F: Field> Table<F> {
    /// used for sha256. also can be used as range constraint.
    /// reference https://zcash.github.io/halo2/design/gadgets/sha256/table16.html
    pub fn spread_table(bits: usize) -> Self {
        let size = 1 << bits;
        let width = 2;
        let key_width = 1; //key is num

        let mut columns = vec![Vec::with_capacity(size); width];
        let mut key_map = Map::new();
        let mut row = 0;
        for key in 0..size {
            let key_spread = key_to_spread(key, bits);
            for (i, v) in vec![F::from(key as u64), F::from(key_spread)]
                .into_iter()
                .enumerate()
            {
                columns[i].push(v);
            }

            key_map.insert(vec![F::from(key as u64)], row);
            row += 1;
        }

        Table {
            id: format!("spread_{}bits", bits),
            index: 0,
            size,
            width,
            key_width,
            columns,
            lookups: Vec::new(),

            key_map,
        }
    }

    /// reference https://zcash.github.io/halo2/design/gadgets/sha256/table16.html
    /// contain another smaller spread table, which 'lookup key' should add an extra '0'.
    pub fn spread_table_2in1(bits: usize, small_bits: usize) -> Self {
        assert!(bits > small_bits);
        let size = 1 << bits;
        let small_size = 1 << small_bits;
        let width = 3;
        let key_width = 2; //key is (num, sign)

        let mut columns = vec![Vec::with_capacity(size); width];
        let mut key_map = Map::new();
        let mut row = 0;
        for key in 0..size {
            let key_spread = key_to_spread(key, bits);

            if key < small_size {
                for (i, v) in vec![F::from(key as u64), F::zero(), F::from(key_spread)]
                    .into_iter()
                    .enumerate()
                {
                    columns[i].push(v);
                }
                key_map.insert(vec![F::from(key as u64), F::zero()], row);
            } else {
                for (i, v) in vec![F::from(key as u64), F::one(), F::from(key_spread)]
                    .into_iter()
                    .enumerate()
                {
                    columns[i].push(v);
                }
                key_map.insert(vec![F::from(key as u64), F::one()], row);
            }

            row += 1;
        }

        Table {
            id: format!("spread_{}bits_{}bits", bits, small_bits),
            index: 0,
            size,
            width,
            key_width,
            columns,
            lookups: Vec::new(),

            key_map,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Sha256Word {
    pub var: Variable,

    pub hvar: Variable,
    pub lvar: Variable,

    pub hvar_spread: Variable,
    pub lvar_spread: Variable,
}

impl Sha256Word {
    /// will constraint range of var, and create eq between var and hi-low vars
    pub fn new_from_32bits_var<F: Field>(
        cs: &mut Composer<F>,
        var: Variable,
    ) -> Result<Self, Error> {
        let value = cs.get_assignment(var);
        if value.into_repr().num_bits() as usize > 32 {
            return Err(Error::VariableOutOfRange(format!(
                "sha256 Word value {}, exceeds 32 bits",
                value
            )));
        }
        let tmp = value.into_repr();
        let value_u64 = tmp.as_ref();
        let value_u64 = value_u64[0];

        let low_value = value_u64 % 65536;
        let hi_value = value_u64 >> 16;

        let low_sign = if low_value < (1u64 << 14) {
            cs.alloc(F::zero())
        } else {
            cs.alloc(F::one())
        };
        let hi_sign = if hi_value < (1u64 << 14) {
            cs.alloc(F::zero())
        } else {
            cs.alloc(F::one())
        };

        // let var = cs.alloc(value);
        let hvar = cs.alloc(F::from(hi_value));
        let lvar = cs.alloc(F::from(low_value));

        let spread16_index = cs.get_table_index("spread_16bits_14bits".to_string());
        assert!(spread16_index != 0);

        let hvar_spread = cs.read_from_table(spread16_index, vec![hvar, hi_sign])?;
        let lvar_spread = cs.read_from_table(spread16_index, vec![lvar, low_sign])?;

        cs.poly_gate(
            vec![
                (lvar, F::one()),
                (hvar, F::from(65536_u64)),
                (var, -F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        Ok(Self {
            var,
            hvar,
            lvar,
            hvar_spread: hvar_spread[0],
            lvar_spread: lvar_spread[0],
        })
    }

    /// will create range constraints (lookup spread).
    /// and NOT create eq constraints between var and hi-low vars
    pub fn new_from_vars<F: Field>(
        cs: &mut Composer<F>,
        var: Variable,
        hvar: Variable,
        lvar: Variable,
    ) -> Result<Self, Error> {
        let value = cs.get_assignment(var);
        let hi_value = cs.get_assignment(hvar);
        let low_value = cs.get_assignment(lvar);

        let tmp = hi_value.into_repr();
        let hi_value_u64 = tmp.as_ref();
        let hi_value_u64 = hi_value_u64[0];

        let tmp = low_value.into_repr();
        let low_value_u64 = tmp.as_ref();
        let low_value_u64 = low_value_u64[0];

        let low_sign = if low_value_u64 < (1u64 << 14) {
            cs.alloc(F::zero())
        } else {
            cs.alloc(F::one())
        };
        let hi_sign = if hi_value_u64 < (1u64 << 14) {
            cs.alloc(F::zero())
        } else {
            cs.alloc(F::one())
        };

        assert_eq!(value, hi_value * F::from(1u64 << 16) + low_value);

        let spread16_index = cs.get_table_index("spread_16bits_14bits".to_string());
        assert!(spread16_index != 0);

        let hvar_spread = cs.read_from_table(spread16_index, vec![hvar, hi_sign])?;
        let lvar_spread = cs.read_from_table(spread16_index, vec![lvar, low_sign])?;

        Ok(Self {
            var,
            hvar,
            lvar,
            hvar_spread: hvar_spread[0],
            lvar_spread: lvar_spread[0],
        })
    }

    /// word = char1|char2|char3|char4
    /// will create range constraints for 8bit(lookup spread). no need 16bit lookup.
    /// message data no need spread. so hi-low vars are null.
    pub fn new_from_8bits<F: Field>(
        cs: &mut Composer<F>,
        char1: Variable,
        char2: Variable,
        char3: Variable,
        char4: Variable,
    ) -> Result<Self, Error> {
        let _ = cs.add_table(Table::spread_table(8));

        let char1value = cs.get_assignment(char1);
        let char2value = cs.get_assignment(char2);
        let char3value = cs.get_assignment(char3);
        let char4value = cs.get_assignment(char4);

        assert!(char1value.into_repr().num_bits() <= 8);
        assert!(char2value.into_repr().num_bits() <= 8);
        assert!(char3value.into_repr().num_bits() <= 8);
        assert!(char4value.into_repr().num_bits() <= 8);

        let value = char1value * F::from(1u64 << 24)
            + char2value * F::from(1u64 << 16)
            + char3value * F::from(1u64 << 8)
            + char4value;

        let var = cs.alloc(value);
        cs.poly_gate(
            vec![
                (var, -F::one()),
                (char4, F::one()),
                (char3, F::from(1u64 << 8)),
                (char2, F::from(1u64 << 16)),
                (char1, F::from(1u64 << 24)),
            ],
            F::zero(),
            F::zero(),
        );

        let spread8_index = cs.get_table_index("spread_8bits".to_string());
        assert!(spread8_index != 0);

        let _ = cs.read_from_table(spread8_index, vec![char1])?;
        let _ = cs.read_from_table(spread8_index, vec![char2])?;
        let _ = cs.read_from_table(spread8_index, vec![char3])?;
        let _ = cs.read_from_table(spread8_index, vec![char4])?;

        Ok(Self {
            var,
            hvar: Composer::<F>::null(),
            lvar: Composer::<F>::null(),
            hvar_spread: Composer::<F>::null(),
            lvar_spread: Composer::<F>::null(),
        })
    }
}

/// compress a full 512bits messages
pub fn sha256_chunk_words_var<F: Field>(
    cs: &mut Composer<F>,
    chunk_messages: &[Sha256Word],
    pre_hash: &[Sha256Word],
) -> Result<Vec<Sha256Word>, Error> {
    assert_eq!(pre_hash.len(), 8);
    assert_eq!(chunk_messages.len(), 16);

    let spread3_index = cs.get_table_index("spread_3bits".to_string());
    assert!(spread3_index != 0);

    // generate 64 words from chunk_messages
    let mut Words = vec![];
    Words.extend_from_slice(chunk_messages);
    for i in 16..64 {
        let (sigma0h, sigma0l) = sha256_sigma_0(cs, &Words[i - 15])?;
        let (sigma1h, sigma1l) = sha256_sigma_1(cs, &Words[i - 2])?;

        let w_minus_7_value = cs.get_assignment(Words[i - 7].var);
        let w_minus_16_value = cs.get_assignment(Words[i - 16].var);
        let sigma0h_value = cs.get_assignment(sigma0h);
        let sigma0l_value = cs.get_assignment(sigma0l);
        let sigma1h_value = cs.get_assignment(sigma1h);
        let sigma1l_value = cs.get_assignment(sigma1l);

        // just add all
        let tmp = sigma0h_value * F::from(1u64 << 16)
            + sigma0l_value
            + sigma1h_value * F::from(1u64 << 16)
            + sigma1l_value;
        let all_add = tmp + w_minus_7_value + w_minus_16_value;
        let all_add = all_add.into_repr();
        let all_add_u64 = all_add.as_ref();
        let all_add_u64 = all_add_u64[0];
        // cal mod 2^32
        let wi_value = all_add_u64 % (1u64 << 32);
        // cal carry
        let carry = all_add_u64 >> 32;
        assert!(carry < 4);

        let low_value = wi_value % 65536;
        let hi_value = wi_value >> 16;

        let wi_var = cs.alloc(F::from(wi_value));

        let carry_var = cs.alloc(F::from(carry));
        let tmp_var = cs.alloc(tmp);

        // range
        let _ = cs.read_from_table(spread3_index, vec![carry_var])?;

        let wi = if cs.program_width == 4 {
            let hvar = cs.alloc(F::from(hi_value));
            let lvar = cs.alloc(F::from(low_value));
            // 2^{16}sigma0_H + sigma0_L + 2^{16}sigma1_H + sigma1_L = (tmp)next
            // tmp + w[i-7] + w[i-16] = 2^{32}carry + (wi)next
            // wi = 2^{16}wi_H + wi_L
            cs.fully_customizable_poly_gates(
                vec![
                    vec![
                        (sigma0h, F::from(1u64 << 16)),
                        (sigma0l, F::one()),
                        (sigma1h, F::from(1u64 << 16)),
                        (sigma1l, F::one()),
                    ],
                    vec![
                        (tmp_var, F::one()),
                        (Words[i - 7].var, F::one()),
                        (Words[i - 16].var, F::one()),
                        (carry_var, -F::from(1u64 << 32)),
                    ],
                    vec![
                        (wi_var, -F::one()),
                        (hvar, F::from(1u64 << 16)),
                        (lvar, F::one()),
                    ],
                ],
                vec![F::zero(), F::zero(), F::zero()],
                vec![F::zero(), F::zero(), F::zero()],
                vec![-F::one(), -F::one(), F::zero()],
            );
            Sha256Word::new_from_vars(cs, wi_var, hvar, lvar)?
        } else {
            let wi = Sha256Word::new_from_32bits_var(cs, wi_var)?;
            cs.poly_gate(
                vec![
                    (tmp_var, -F::one()),
                    (sigma0h, F::from(1u64 << 16)),
                    (sigma0l, F::one()),
                    (sigma1h, F::from(1u64 << 16)),
                    (sigma1l, F::one()),
                ],
                F::zero(),
                F::zero(),
            );
            cs.poly_gate(
                vec![
                    (wi.var, -F::one()),
                    (carry_var, -F::from(1u64 << 32)),
                    (Words[i - 7].var, F::one()),
                    (Words[i - 16].var, F::one()),
                    (tmp_var, F::one()),
                ],
                F::zero(),
                F::zero(),
            );
            wi
        };

        Words.push(wi);
    }

    // init a b c d e f g h
    let mut tmp_hash = vec![];
    for &elem in pre_hash {
        tmp_hash.push(elem);
    }
    // 64 rounds
    for i in 0..64 {
        let wi_value = cs.get_assignment(Words[i].var);
        let H_value = cs.get_assignment(tmp_hash[7].var);
        let D_value = cs.get_assignment(tmp_hash[3].var);

        let chi = sha256_Ch(cs, &tmp_hash[4], &tmp_hash[5], &tmp_hash[6])?;
        let chi_value = cs.get_assignment(chi);

        let (sum_1_hi, sum_1_low) = sha256_sum_1(cs, &tmp_hash[4])?;
        let sum_1_hi_value = cs.get_assignment(sum_1_hi);
        let sum_1_low_value = cs.get_assignment(sum_1_low);

        let (sum_0_hi, sum_0_low) = sha256_sum_0(cs, &tmp_hash[0])?;
        let sum_0_hi_value = cs.get_assignment(sum_0_hi);
        let sum_0_low_value = cs.get_assignment(sum_0_low);

        let (maj_hi, maj_low) = sha256_Maj(cs, &tmp_hash[0], &tmp_hash[1], &tmp_hash[2])?;
        let maj_hi_value = cs.get_assignment(maj_hi);
        let maj_low_value = cs.get_assignment(maj_low);

        // cal new E and A
        let tmp0 = F::from(BigUint::parse_bytes(SHA256CONSTS[i].as_bytes(), 16).unwrap())
            + wi_value
            + H_value
            + sum_1_hi_value * F::from(1u64 << 16)
            + sum_1_low_value;
        let tmp0var = cs.alloc(tmp0);

        // E new: just add
        let Eadd = tmp0 + chi_value + D_value;
        let Eadd = Eadd.into_repr();
        let Eadd_u64 = Eadd.as_ref();
        let Eadd_u64 = Eadd_u64[0];
        // cal mod 2^32
        let Enew_value = Eadd_u64 % (1u64 << 32);
        // cal carryE
        let carryE = Eadd_u64 >> 32;
        assert!(carryE < 6);

        let Elow_value = Enew_value % 65536;
        let Ehi_value = Enew_value >> 16;

        let Enew_var = cs.alloc(F::from(Enew_value));

        let carryE_var = cs.alloc(F::from(carryE));
        // range
        let _ = cs.read_from_table(spread3_index, vec![carryE_var])?;

        let Enew = if cs.program_width == 4 {
            let Enew_hvar = cs.alloc(F::from(Ehi_value));
            let Enew_lvar = cs.alloc(F::from(Elow_value));
            // Wt + H + 2^{16}sum1_H + sum1_L + Kt = (tmp0)next
            // tmp0 + Ch + D = 2^{32}carry + (Enew)next
            // Enew = 2^{16}Enew_H + Enew_L
            cs.fully_customizable_poly_gates(
                vec![
                    vec![
                        (sum_1_hi, F::from(1u64 << 16)),
                        (sum_1_low, F::one()),
                        (Words[i].var, F::one()),
                        (tmp_hash[7].var, F::one()),
                    ],
                    vec![
                        (tmp0var, F::one()),
                        (chi, F::one()),
                        (tmp_hash[3].var, F::one()),
                        (carryE_var, -F::from(1u64 << 32)),
                    ],
                    vec![
                        (Enew_var, -F::one()),
                        (Enew_hvar, F::from(1u64 << 16)),
                        (Enew_lvar, F::one()),
                    ],
                ],
                vec![F::zero(), F::zero(), F::zero()],
                vec![
                    F::from(BigUint::parse_bytes(SHA256CONSTS[i].as_bytes(), 16).unwrap()),
                    F::zero(),
                    F::zero(),
                ],
                vec![-F::one(), -F::one(), F::zero()],
            );
            Sha256Word::new_from_vars(cs, Enew_var, Enew_hvar, Enew_lvar)?
        } else {
            let Enew = Sha256Word::new_from_32bits_var(cs, Enew_var)?;
            cs.poly_gate(
                vec![
                    (tmp0var, -F::one()),
                    (sum_1_hi, F::from(1u64 << 16)),
                    (sum_1_low, F::one()),
                    (Words[i].var, F::one()),
                    (tmp_hash[7].var, F::one()),
                ],
                F::zero(),
                F::from(BigUint::parse_bytes(SHA256CONSTS[i].as_bytes(), 16).unwrap()),
            );
            cs.poly_gate(
                vec![
                    (Enew.var, -F::one()),
                    (carryE_var, -F::from(1u64 << 32)),
                    (chi, F::one()),
                    (tmp_hash[3].var, F::one()),
                    (tmp0var, F::one()),
                ],
                F::zero(),
                F::zero(),
            );
            Enew
        };

        // A new: just add
        let tmp2 = tmp0 + chi_value + maj_hi_value * F::from(1u64 << 16) + maj_low_value;
        let Aadd = tmp2 + sum_0_hi_value * F::from(1u64 << 16) + sum_0_low_value;
        let Aadd = Aadd.into_repr();
        let Aadd_u64 = Aadd.as_ref();
        let Aadd_u64 = Aadd_u64[0];
        // cal mod 2^32
        let Anew_value = Aadd_u64 % (1u64 << 32);
        // cal carryA
        let carryA = Aadd_u64 >> 32;
        assert!(carryA < 7);

        let Alow_value = Anew_value % 65536;
        let Ahi_value = Anew_value >> 16;

        let Anew_var = cs.alloc(F::from(Anew_value));

        let carryA_var = cs.alloc(F::from(carryA));
        let tmp2var = cs.alloc(tmp2);
        // range
        let _ = cs.read_from_table(spread3_index, vec![carryA_var])?;

        let Anew = if cs.program_width == 4 {
            let Anew_hvar = cs.alloc(F::from(Ahi_value));
            let Anew_lvar = cs.alloc(F::from(Alow_value));
            // tmp0 + Ch + 2^{16}Maj_h + Maj_l = (tmp2)next
            // tmp2 + 2^{16}sum0_H + sum0_L = 2^{32}carry + (Anew)next
            // Anew = 2^{16}Anew_H + Anew_L
            cs.fully_customizable_poly_gates(
                vec![
                    vec![
                        (tmp0var, F::one()),
                        (chi, F::one()),
                        (maj_hi, F::from(1u64 << 16)),
                        (maj_low, F::one()),
                    ],
                    vec![
                        (tmp2var, F::one()),
                        (sum_0_hi, F::from(1u64 << 16)),
                        (sum_0_low, F::one()),
                        (carryA_var, -F::from(1u64 << 32)),
                    ],
                    vec![
                        (Anew_var, -F::one()),
                        (Anew_hvar, F::from(1u64 << 16)),
                        (Anew_lvar, F::one()),
                    ],
                ],
                vec![F::zero(), F::zero(), F::zero()],
                vec![F::zero(), F::zero(), F::zero()],
                vec![-F::one(), -F::one(), F::zero()],
            );
            Sha256Word::new_from_vars(cs, Anew_var, Anew_hvar, Anew_lvar)?
        } else {
            let Anew = Sha256Word::new_from_32bits_var(cs, Anew_var)?;
            cs.poly_gate(
                vec![
                    (tmp2var, -F::one()),
                    (maj_hi, F::from(1u64 << 16)),
                    (maj_low, F::one()),
                    (chi, F::one()),
                    (tmp0var, F::one()),
                ],
                F::zero(),
                F::zero(),
            );
            cs.poly_gate(
                vec![
                    (Anew.var, -F::one()),
                    (carryA_var, -F::from(1u64 << 32)),
                    (sum_0_hi, F::from(1u64 << 16)),
                    (sum_0_low, F::one()),
                    (tmp2var, F::one()),
                ],
                F::zero(),
                F::zero(),
            );
            Anew
        };

        //update tmp_hash[]
        tmp_hash[7] = tmp_hash[6];
        tmp_hash[6] = tmp_hash[5];
        tmp_hash[5] = tmp_hash[4];
        tmp_hash[4] = Enew;
        tmp_hash[3] = tmp_hash[2];
        tmp_hash[2] = tmp_hash[1];
        tmp_hash[1] = tmp_hash[0];
        tmp_hash[0] = Anew;
    }

    // output = pre_hash + abcdefgh
    for i in 0..8 {
        let tmphash_value = cs.get_assignment(tmp_hash[i].var);
        let prehash_value = cs.get_assignment(pre_hash[i].var);

        let addv = tmphash_value + prehash_value;
        let addv = addv.into_repr();
        let addv_u64 = addv.as_ref();
        let addv_u64 = addv_u64[0];
        // cal mod 2^32
        let hash_value = addv_u64 % (1u64 << 32);
        // cal carry
        let carry = addv_u64 >> 32;
        assert!(carry < 2);

        let hash_var = cs.alloc(F::from(hash_value));
        let hash = Sha256Word::new_from_32bits_var(cs, hash_var)?;

        let carry_var = cs.alloc(F::from(carry));
        // range
        cs.poly_gate(
            vec![(carry_var, -F::one()), (carry_var, F::zero())],
            F::one(),
            F::zero(),
        );

        cs.poly_gate(
            vec![
                (hash.var, -F::one()),
                (carry_var, -F::from(1u64 << 32)),
                (tmp_hash[i].var, F::one()),
                (pre_hash[i].var, F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        //update tmp_hash[] as output
        tmp_hash[i] = hash;
    }

    Ok(tmp_hash)
}

/// X = 2^{18}d + 2^{7}c + 2^{3}b  +a
pub struct Sha256sigma0form {
    pub var: Variable,

    pub a: Variable,
    pub b: Variable,
    pub c: Variable,
    pub d: Variable,

    pub a_spread: Variable,
    pub b_spread: Variable,
    pub c_spread: Variable,
    pub d_spread: Variable,
}

impl Sha256sigma0form {
    /// split the word into a|b|c|d (3,4,11,14)bits
    fn new<F: Field>(cs: &mut Composer<F>, word: &Sha256Word) -> Result<Self, Error> {
        let value = cs.get_assignment(word.var);

        let tmp = value.into_repr();
        let value_u64 = tmp.as_ref();
        let mut value_u64 = value_u64[0];

        let a_value = value_u64 % 8;
        value_u64 >>= 3;
        let b_value = value_u64 % 16;
        value_u64 >>= 4;
        let c_value = value_u64 % 2048;
        value_u64 >>= 11;
        let d_value = value_u64;
        value_u64 >>= 14;
        assert_eq!(value_u64, 0);

        let a = cs.alloc(F::from(a_value));
        let b = cs.alloc(F::from(b_value));
        let c = cs.alloc(F::from(c_value));
        let d = cs.alloc(F::from(d_value));

        let spread3_index = cs.get_table_index("spread_3bits".to_string());
        assert!(spread3_index != 0);

        let spread_14_index = cs.get_table_index("spread_16bits_14bits".to_string());
        assert!(spread_14_index != 0);
        let spread_4_index = cs.get_table_index("spread_5bits_4bits".to_string());
        assert!(spread_4_index != 0);
        let spread_11_index = cs.get_table_index("spread_13bits_11bits".to_string());
        assert!(spread_11_index != 0);

        let a_spread = cs.read_from_table(spread3_index, vec![a])?;
        let b_spread = cs.read_from_table(spread_4_index, vec![b, Composer::<F>::null()])?;
        let c_spread = cs.read_from_table(spread_11_index, vec![c, Composer::<F>::null()])?;
        let d_spread = cs.read_from_table(spread_14_index, vec![d, Composer::<F>::null()])?;

        if cs.program_width == 4 {
            cs.poly_gate_with_next(
                vec![
                    (a, F::one()),
                    (b, F::from(8_u64)),      //2^(3)
                    (c, F::from(128_u64)),    //2^(3+4)
                    (d, F::from(1u64 << 18)), //2^(3+4+11)
                ],
                F::zero(),
                F::zero(),
                vec![(word.var, -F::one())],
            );
        } else if cs.program_width >= 5 {
            cs.poly_gate(
                vec![
                    (word.var, -F::one()),
                    (a, F::one()),
                    (b, F::from(8_u64)),      //2^(3)
                    (c, F::from(128_u64)),    //2^(3+4)
                    (d, F::from(1u64 << 18)), //2^(3+4+11)
                ],
                F::zero(),
                F::zero(),
            );
        }

        Ok(Self {
            var: word.var,
            a,
            b,
            c,
            d,
            a_spread: a_spread[0],
            b_spread: b_spread[0],
            c_spread: c_spread[0],
            d_spread: d_spread[0],
        })
    }
}

/// σ0 function
fn sha256_sigma_0<F: Field>(
    cs: &mut Composer<F>,
    word: &Sha256Word,
) -> Result<(Variable, Variable), Error> {
    let split_form = Sha256sigma0form::new(cs, word)?;

    let a_spread_value = cs.get_assignment(split_form.a_spread);
    let b_spread_value = cs.get_assignment(split_form.b_spread);
    let c_spread_value = cs.get_assignment(split_form.c_spread);
    let d_spread_value = cs.get_assignment(split_form.d_spread);

    let R = a_spread_value * F::from((1u64 << 50) + (1u64 << 28))
        + b_spread_value * F::from(1u64 + (1u64 << 56) + (1u64 << 34))
        + c_spread_value * F::from(1u64 + (1u64 << 42) + (1u64 << 8))
        + d_spread_value * F::from(1u64 + (1u64 << 30) + (1u64 << 22));
    assert!(R.into_repr().num_bits() as usize <= 64);

    let Rvar = cs.alloc(R);
    // R' = Yd'+Yc'+Yb'+Ya'
    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (split_form.a_spread, F::from((1u64 << 50) + (1u64 << 28))),
                (
                    split_form.b_spread,
                    F::from(1u64 + (1u64 << 56) + (1u64 << 34)),
                ),
                (
                    split_form.c_spread,
                    F::from(1u64 + (1u64 << 42) + (1u64 << 8)),
                ),
                (
                    split_form.d_spread,
                    F::from(1u64 + (1u64 << 30) + (1u64 << 22)),
                ),
            ],
            F::zero(),
            F::zero(),
            vec![(Rvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Rvar, -F::one()),
                (split_form.a_spread, F::from((1u64 << 50) + (1u64 << 28))),
                (
                    split_form.b_spread,
                    F::from(1u64 + (1u64 << 56) + (1u64 << 34)),
                ),
                (
                    split_form.c_spread,
                    F::from(1u64 + (1u64 << 42) + (1u64 << 8)),
                ),
                (
                    split_form.d_spread,
                    F::from(1u64 + (1u64 << 30) + (1u64 << 22)),
                ),
            ],
            F::zero(),
            F::zero(),
        );
    }

    let tmp = R.into_repr();
    let R_u64 = tmp.as_ref();
    let R_u64 = R_u64[0];

    let mut Reven_hi = 0u64;
    let mut Reven_low = 0u64;
    let mut Rodd_hi = 0u64;
    let mut Rodd_low = 0u64;

    let mut tmp = R_u64;
    // low
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Reven_low += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Rodd_low += 1 << i;
        }
    }
    // hi
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Reven_hi += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Rodd_hi += 1 << i;
        }
    }

    let Reven_hi_sign = if Reven_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Reven_low_sign = if Reven_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Rodd_hi_sign = if Rodd_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Rodd_low_sign = if Rodd_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };

    let Reven_hi = cs.alloc(F::from(Reven_hi));
    let Reven_low = cs.alloc(F::from(Reven_low));
    let Rodd_hi = cs.alloc(F::from(Rodd_hi));
    let Rodd_low = cs.alloc(F::from(Rodd_low));

    let spread16_index = cs.get_table_index("spread_16bits_14bits".to_string());
    assert!(spread16_index != 0);

    let Reven_hi_spread = cs.read_from_table(spread16_index, vec![Reven_hi, Reven_hi_sign])?;
    let Reven_low_spread = cs.read_from_table(spread16_index, vec![Reven_low, Reven_low_sign])?;
    let Rodd_hi_spread = cs.read_from_table(spread16_index, vec![Rodd_hi, Rodd_hi_sign])?;
    let Rodd_low_spread = cs.read_from_table(spread16_index, vec![Rodd_low, Rodd_low_sign])?;

    // R' = 2^{32}Reven_H' + Reven_L' + 2^{32}2Rodd_H' + 2Rodd_L'
    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (Reven_hi_spread[0], F::from(1u64 << 32)),
                (Reven_low_spread[0], F::one()),
                (Rodd_hi_spread[0], F::from(1u64 << 33)),
                (Rodd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
            vec![(Rvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Rvar, -F::one()),
                (Reven_hi_spread[0], F::from(1u64 << 32)),
                (Reven_low_spread[0], F::one()),
                (Rodd_hi_spread[0], F::from(1u64 << 33)),
                (Rodd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
        );
    }

    // hi, low
    Ok((Reven_hi, Reven_low))
}

/// X = 2^{19}d + 2^{17}c + 2^{10}b  +a
pub struct Sha256sigma1form {
    pub var: Variable,

    pub a: Variable,
    pub b: Variable,
    pub c: Variable,
    pub d: Variable,

    pub a_spread: Variable,
    pub b_spread: Variable,
    pub c_spread: Variable,
    pub d_spread: Variable,
}

impl Sha256sigma1form {
    /// split the word into a|b|c|d (10,7,2,13)bits
    fn new<F: Field>(cs: &mut Composer<F>, word: &Sha256Word) -> Result<Self, Error> {
        let value = cs.get_assignment(word.var);

        let tmp = value.into_repr();
        let value_u64 = tmp.as_ref();
        let mut value_u64 = value_u64[0];

        let a_value = value_u64 % 1024;
        value_u64 >>= 10;
        let b_value = value_u64 % 128;
        value_u64 >>= 7;
        let c_value = value_u64 % 4;
        value_u64 >>= 2;
        let d_value = value_u64;
        value_u64 >>= 13;
        assert_eq!(value_u64, 0);

        let a_sign = if a_value < (1u64 << 9) {
            cs.alloc(F::zero())
        } else {
            cs.alloc(F::one())
        };
        let b_sign = if b_value < (1u64 << 6) {
            cs.alloc(F::zero())
        } else {
            cs.alloc(F::one())
        };
        let d_sign = if d_value < (1u64 << 11) {
            cs.alloc(F::zero())
        } else {
            cs.alloc(F::one())
        };

        let a = cs.alloc(F::from(a_value));
        let b = cs.alloc(F::from(b_value));
        let c = cs.alloc(F::from(c_value));
        let d = cs.alloc(F::from(d_value));

        let spread2_index = cs.get_table_index("spread_2bits".to_string());
        assert!(spread2_index != 0);

        let spread_7_index = cs.get_table_index("spread_7bits_6bits".to_string());
        assert!(spread_7_index != 0);
        let spread_10_index = cs.get_table_index("spread_10bits_9bits".to_string());
        assert!(spread_10_index != 0);
        let spread_13_index = cs.get_table_index("spread_13bits_11bits".to_string());
        assert!(spread_13_index != 0);

        let a_spread = cs.read_from_table(spread_10_index, vec![a, a_sign])?;
        let b_spread = cs.read_from_table(spread_7_index, vec![b, b_sign])?;
        let c_spread = cs.read_from_table(spread2_index, vec![c])?;
        let d_spread = cs.read_from_table(spread_13_index, vec![d, d_sign])?;

        if cs.program_width == 4 {
            cs.poly_gate_with_next(
                vec![
                    (a, F::one()),
                    (b, F::from(1024_u64)),   //2^(10)
                    (c, F::from(1u64 << 17)), //2^(10+7)
                    (d, F::from(1u64 << 19)), //2^(10+7+2)
                ],
                F::zero(),
                F::zero(),
                vec![(word.var, -F::one())],
            );
        } else if cs.program_width >= 5 {
            cs.poly_gate(
                vec![
                    (word.var, -F::one()),
                    (a, F::one()),
                    (b, F::from(1024_u64)),   //2^(10)
                    (c, F::from(1u64 << 17)), //2^(10+7)
                    (d, F::from(1u64 << 19)), //2^(10+7+2)
                ],
                F::zero(),
                F::zero(),
            );
        }

        Ok(Self {
            var: word.var,
            a,
            b,
            c,
            d,
            a_spread: a_spread[0],
            b_spread: b_spread[0],
            c_spread: c_spread[0],
            d_spread: d_spread[0],
        })
    }
}

/// σ1 function
fn sha256_sigma_1<F: Field>(
    cs: &mut Composer<F>,
    word: &Sha256Word,
) -> Result<(Variable, Variable), Error> {
    let split_form = Sha256sigma1form::new(cs, word)?;

    let a_spread_value = cs.get_assignment(split_form.a_spread);
    let b_spread_value = cs.get_assignment(split_form.b_spread);
    let c_spread_value = cs.get_assignment(split_form.c_spread);
    let d_spread_value = cs.get_assignment(split_form.d_spread);

    let R = a_spread_value * F::from((1u64 << 30) + (1u64 << 26))
        + b_spread_value * F::from(1u64 + (1u64 << 50) + (1u64 << 46))
        + c_spread_value * F::from(1u64 + (1u64 << 60) + (1u64 << 14))
        + d_spread_value * F::from(1u64 + (1u64 << 4) + (1u64 << 18));
    assert!(R.into_repr().num_bits() as usize <= 64);

    let Rvar = cs.alloc(R);
    // R' = Yd'+Yc'+Yb'+Ya'
    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (split_form.a_spread, F::from((1u64 << 30) + (1u64 << 26))),
                (
                    split_form.b_spread,
                    F::from(1u64 + (1u64 << 50) + (1u64 << 46)),
                ),
                (
                    split_form.c_spread,
                    F::from(1u64 + (1u64 << 60) + (1u64 << 14)),
                ),
                (
                    split_form.d_spread,
                    F::from(1u64 + (1u64 << 4) + (1u64 << 18)),
                ),
            ],
            F::zero(),
            F::zero(),
            vec![(Rvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Rvar, -F::one()),
                (split_form.a_spread, F::from((1u64 << 30) + (1u64 << 26))),
                (
                    split_form.b_spread,
                    F::from(1u64 + (1u64 << 50) + (1u64 << 46)),
                ),
                (
                    split_form.c_spread,
                    F::from(1u64 + (1u64 << 60) + (1u64 << 14)),
                ),
                (
                    split_form.d_spread,
                    F::from(1u64 + (1u64 << 4) + (1u64 << 18)),
                ),
            ],
            F::zero(),
            F::zero(),
        );
    }

    let tmp = R.into_repr();
    let R_u64 = tmp.as_ref();
    let R_u64 = R_u64[0];

    let mut Reven_hi = 0u64;
    let mut Reven_low = 0u64;
    let mut Rodd_hi = 0u64;
    let mut Rodd_low = 0u64;

    let mut tmp = R_u64;
    // low
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Reven_low += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Rodd_low += 1 << i;
        }
    }
    // hi
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Reven_hi += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Rodd_hi += 1 << i;
        }
    }

    let Reven_hi_sign = if Reven_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Reven_low_sign = if Reven_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Rodd_hi_sign = if Rodd_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Rodd_low_sign = if Rodd_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };

    let Reven_hi = cs.alloc(F::from(Reven_hi));
    let Reven_low = cs.alloc(F::from(Reven_low));
    let Rodd_hi = cs.alloc(F::from(Rodd_hi));
    let Rodd_low = cs.alloc(F::from(Rodd_low));

    let spread16_index = cs.get_table_index("spread_16bits_14bits".to_string());
    assert!(spread16_index != 0);

    let Reven_hi_spread = cs.read_from_table(spread16_index, vec![Reven_hi, Reven_hi_sign])?;
    let Reven_low_spread = cs.read_from_table(spread16_index, vec![Reven_low, Reven_low_sign])?;
    let Rodd_hi_spread = cs.read_from_table(spread16_index, vec![Rodd_hi, Rodd_hi_sign])?;
    let Rodd_low_spread = cs.read_from_table(spread16_index, vec![Rodd_low, Rodd_low_sign])?;

    // R' = 2^{32}Reven_H' + Reven_L' + 2^{32}2Rodd_H' + 2Rodd_L'
    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (Reven_hi_spread[0], F::from(1u64 << 32)),
                (Reven_low_spread[0], F::one()),
                (Rodd_hi_spread[0], F::from(1u64 << 33)),
                (Rodd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
            vec![(Rvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Rvar, -F::one()),
                (Reven_hi_spread[0], F::from(1u64 << 32)),
                (Reven_low_spread[0], F::one()),
                (Rodd_hi_spread[0], F::from(1u64 << 33)),
                (Rodd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
        );
    }

    // hi, low
    Ok((Reven_hi, Reven_low))
}

/// X = 2^{22}d + 2^{13}c + 2^{2}b  +a
pub struct Sha256sum0form {
    pub var: Variable,

    pub a: Variable,
    pub b: Variable,
    pub c: Variable,
    pub d: Variable,

    pub a_spread: Variable,
    pub b_spread: Variable,
    pub c_spread: Variable,
    pub d_spread: Variable,
}

impl Sha256sum0form {
    /// split the word into a|b|c|d (2,11,9,10)bits
    fn new<F: Field>(cs: &mut Composer<F>, word: &Sha256Word) -> Result<Self, Error> {
        let value = cs.get_assignment(word.var);

        let tmp = value.into_repr();
        let value_u64 = tmp.as_ref();
        let mut value_u64 = value_u64[0];

        let a_value = value_u64 % 4;
        value_u64 >>= 2;
        let b_value = value_u64 % 2048;
        value_u64 >>= 11;
        let c_value = value_u64 % 512;
        value_u64 >>= 9;
        let d_value = value_u64;
        value_u64 >>= 10;
        assert_eq!(value_u64, 0);

        let d_sign = if d_value < (1u64 << 9) {
            cs.alloc(F::zero())
        } else {
            cs.alloc(F::one())
        };

        let a = cs.alloc(F::from(a_value));
        let b = cs.alloc(F::from(b_value));
        let c = cs.alloc(F::from(c_value));
        let d = cs.alloc(F::from(d_value));

        let spread2_index = cs.get_table_index("spread_2bits".to_string());
        assert!(spread2_index != 0);

        let spread_9_index = cs.get_table_index("spread_10bits_9bits".to_string());
        assert!(spread_9_index != 0);
        let spread_10_index = cs.get_table_index("spread_10bits_9bits".to_string());
        assert!(spread_10_index != 0);
        let spread_11_index = cs.get_table_index("spread_13bits_11bits".to_string());
        assert!(spread_11_index != 0);

        let a_spread = cs.read_from_table(spread2_index, vec![a])?;
        let b_spread = cs.read_from_table(spread_11_index, vec![b, Composer::<F>::null()])?;
        let c_spread = cs.read_from_table(spread_9_index, vec![c, Composer::<F>::null()])?;
        let d_spread = cs.read_from_table(spread_10_index, vec![d, d_sign])?;

        if cs.program_width == 4 {
            cs.poly_gate_with_next(
                vec![
                    (a, F::one()),
                    (b, F::from(4_u64)),      //2^(2)
                    (c, F::from(1u64 << 13)), //2^(11+2)
                    (d, F::from(1u64 << 22)), //2^(9+11+2)
                ],
                F::zero(),
                F::zero(),
                vec![(word.var, -F::one())],
            );
        } else if cs.program_width >= 5 {
            cs.poly_gate(
                vec![
                    (word.var, -F::one()),
                    (a, F::one()),
                    (b, F::from(4_u64)),      //2^(2)
                    (c, F::from(1u64 << 13)), //2^(11+2)
                    (d, F::from(1u64 << 22)), //2^(9+11+2)
                ],
                F::zero(),
                F::zero(),
            );
        }

        Ok(Self {
            var: word.var,
            a,
            b,
            c,
            d,
            a_spread: a_spread[0],
            b_spread: b_spread[0],
            c_spread: c_spread[0],
            d_spread: d_spread[0],
        })
    }
}

/// X = 2^{25}d + 2^{11}c + 2^{6}b  +a
pub struct Sha256sum1form {
    pub var: Variable,

    pub a: Variable,
    pub b: Variable,
    pub c: Variable,
    pub d: Variable,

    pub a_spread: Variable,
    pub b_spread: Variable,
    pub c_spread: Variable,
    pub d_spread: Variable,
}

impl Sha256sum1form {
    /// split the word into a|b|c|d (6,5,14,7)bits
    pub fn new<F: Field>(cs: &mut Composer<F>, word: &Sha256Word) -> Result<Self, Error> {
        let value = cs.get_assignment(word.var);

        let tmp = value.into_repr();
        let value_u64 = tmp.as_ref();
        let mut value_u64 = value_u64[0];

        let a_value = value_u64 % 64;
        value_u64 >>= 6;
        let b_value = value_u64 % 32;
        value_u64 >>= 5;
        let c_value = value_u64 % (1u64 << 14);
        value_u64 >>= 14;
        let d_value = value_u64;
        value_u64 >>= 7;
        assert_eq!(value_u64, 0);

        let b_sign = if b_value < (1u64 << 4) {
            cs.alloc(F::zero())
        } else {
            cs.alloc(F::one())
        };
        let d_sign = if d_value < (1u64 << 6) {
            cs.alloc(F::zero())
        } else {
            cs.alloc(F::one())
        };

        let a = cs.alloc(F::from(a_value));
        let b = cs.alloc(F::from(b_value));
        let c = cs.alloc(F::from(c_value));
        let d = cs.alloc(F::from(d_value));

        let spread_6_index = cs.get_table_index("spread_7bits_6bits".to_string());
        assert!(spread_6_index != 0);
        let spread_7_index = cs.get_table_index("spread_7bits_6bits".to_string());
        assert!(spread_7_index != 0);
        let spread_14_index = cs.get_table_index("spread_16bits_14bits".to_string());
        assert!(spread_14_index != 0);
        let spread_5_index = cs.get_table_index("spread_5bits_4bits".to_string());
        assert!(spread_5_index != 0);

        let a_spread = cs.read_from_table(spread_6_index, vec![a, Composer::<F>::null()])?;
        let b_spread = cs.read_from_table(spread_5_index, vec![b, b_sign])?;
        let c_spread = cs.read_from_table(spread_14_index, vec![c, Composer::<F>::null()])?;
        let d_spread = cs.read_from_table(spread_7_index, vec![d, d_sign])?;

        if cs.program_width == 4 {
            cs.poly_gate_with_next(
                vec![
                    (a, F::one()),
                    (b, F::from(64_u64)),     //2^(6)
                    (c, F::from(1u64 << 11)), //2^(6+5)
                    (d, F::from(1u64 << 25)), //2^(6+5+14)
                ],
                F::zero(),
                F::zero(),
                vec![(word.var, -F::one())],
            );
        } else if cs.program_width >= 5 {
            cs.poly_gate(
                vec![
                    (word.var, -F::one()),
                    (a, F::one()),
                    (b, F::from(64_u64)),     //2^(6)
                    (c, F::from(1u64 << 11)), //2^(6+5)
                    (d, F::from(1u64 << 25)), //2^(6+5+14)
                ],
                F::zero(),
                F::zero(),
            );
        }

        Ok(Self {
            var: word.var,
            a,
            b,
            c,
            d,
            a_spread: a_spread[0],
            b_spread: b_spread[0],
            c_spread: c_spread[0],
            d_spread: d_spread[0],
        })
    }
}

/// Σ0 function
pub fn sha256_sum_0<F: Field>(
    cs: &mut Composer<F>,
    word: &Sha256Word,
) -> Result<(Variable, Variable), Error> {
    let split_form = Sha256sum0form::new(cs, word)?;

    let a_spread_value = cs.get_assignment(split_form.a_spread);
    let b_spread_value = cs.get_assignment(split_form.b_spread);
    let c_spread_value = cs.get_assignment(split_form.c_spread);
    let d_spread_value = cs.get_assignment(split_form.d_spread);

    let R = a_spread_value * F::from((1u64 << 60) + (1u64 << 38) + (1u64 << 20))
        + b_spread_value * F::from(1u64 + (1u64 << 42) + (1u64 << 24))
        + c_spread_value * F::from(1u64 + (1u64 << 22) + (1u64 << 46))
        + d_spread_value * F::from(1u64 + (1u64 << 40) + (1u64 << 18));
    assert!(R.into_repr().num_bits() as usize <= 64);

    let Rvar = cs.alloc(R);
    // R' = Yd'+Yc'+Yb'+Ya'
    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (
                    split_form.a_spread,
                    F::from((1u64 << 60) + (1u64 << 38) + (1u64 << 20)),
                ),
                (
                    split_form.b_spread,
                    F::from(1u64 + (1u64 << 42) + (1u64 << 24)),
                ),
                (
                    split_form.c_spread,
                    F::from(1u64 + (1u64 << 22) + (1u64 << 46)),
                ),
                (
                    split_form.d_spread,
                    F::from(1u64 + (1u64 << 40) + (1u64 << 18)),
                ),
            ],
            F::zero(),
            F::zero(),
            vec![(Rvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Rvar, -F::one()),
                (
                    split_form.a_spread,
                    F::from((1u64 << 60) + (1u64 << 38) + (1u64 << 20)),
                ),
                (
                    split_form.b_spread,
                    F::from(1u64 + (1u64 << 42) + (1u64 << 24)),
                ),
                (
                    split_form.c_spread,
                    F::from(1u64 + (1u64 << 22) + (1u64 << 46)),
                ),
                (
                    split_form.d_spread,
                    F::from(1u64 + (1u64 << 40) + (1u64 << 18)),
                ),
            ],
            F::zero(),
            F::zero(),
        );
    }

    let tmp = R.into_repr();
    let R_u64 = tmp.as_ref();
    let R_u64 = R_u64[0];

    let mut Reven_hi = 0u64;
    let mut Reven_low = 0u64;
    let mut Rodd_hi = 0u64;
    let mut Rodd_low = 0u64;

    let mut tmp = R_u64;
    // low
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Reven_low += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Rodd_low += 1 << i;
        }
    }
    // hi
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Reven_hi += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Rodd_hi += 1 << i;
        }
    }

    let Reven_hi_sign = if Reven_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Reven_low_sign = if Reven_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Rodd_hi_sign = if Rodd_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Rodd_low_sign = if Rodd_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };

    let Reven_hi = cs.alloc(F::from(Reven_hi));
    let Reven_low = cs.alloc(F::from(Reven_low));
    let Rodd_hi = cs.alloc(F::from(Rodd_hi));
    let Rodd_low = cs.alloc(F::from(Rodd_low));

    let spread16_index = cs.get_table_index("spread_16bits_14bits".to_string());
    assert!(spread16_index != 0);

    let Reven_hi_spread = cs.read_from_table(spread16_index, vec![Reven_hi, Reven_hi_sign])?;
    let Reven_low_spread = cs.read_from_table(spread16_index, vec![Reven_low, Reven_low_sign])?;
    let Rodd_hi_spread = cs.read_from_table(spread16_index, vec![Rodd_hi, Rodd_hi_sign])?;
    let Rodd_low_spread = cs.read_from_table(spread16_index, vec![Rodd_low, Rodd_low_sign])?;

    // R' = 2^{32}Reven_H' + Reven_L' + 2^{32}2Rodd_H' + 2Rodd_L'
    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (Reven_hi_spread[0], F::from(1u64 << 32)),
                (Reven_low_spread[0], F::one()),
                (Rodd_hi_spread[0], F::from(1u64 << 33)),
                (Rodd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
            vec![(Rvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Rvar, -F::one()),
                (Reven_hi_spread[0], F::from(1u64 << 32)),
                (Reven_low_spread[0], F::one()),
                (Rodd_hi_spread[0], F::from(1u64 << 33)),
                (Rodd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
        );
    }

    // hi, low
    Ok((Reven_hi, Reven_low))
}

/// Σ1 function
pub fn sha256_sum_1<F: Field>(
    cs: &mut Composer<F>,
    word: &Sha256Word,
) -> Result<(Variable, Variable), Error> {
    let split_form = Sha256sum1form::new(cs, word)?;

    let a_spread_value = cs.get_assignment(split_form.a_spread);
    let b_spread_value = cs.get_assignment(split_form.b_spread);
    let c_spread_value = cs.get_assignment(split_form.c_spread);
    let d_spread_value = cs.get_assignment(split_form.d_spread);

    let R = a_spread_value * F::from((1u64 << 52) + (1u64 << 42) + (1u64 << 14))
        + b_spread_value * F::from(1u64 + (1u64 << 54) + (1u64 << 26))
        + c_spread_value * F::from(1u64 + (1u64 << 36) + (1u64 << 10))
        + d_spread_value * F::from(1u64 + (1u64 << 38) + (1u64 << 28));
    assert!(R.into_repr().num_bits() as usize <= 64);

    let Rvar = cs.alloc(R);
    // R' = Yd'+Yc'+Yb'+Ya'
    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (
                    split_form.a_spread,
                    F::from((1u64 << 52) + (1u64 << 42) + (1u64 << 14)),
                ),
                (
                    split_form.b_spread,
                    F::from(1u64 + (1u64 << 54) + (1u64 << 26)),
                ),
                (
                    split_form.c_spread,
                    F::from(1u64 + (1u64 << 36) + (1u64 << 10)),
                ),
                (
                    split_form.d_spread,
                    F::from(1u64 + (1u64 << 38) + (1u64 << 28)),
                ),
            ],
            F::zero(),
            F::zero(),
            vec![(Rvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Rvar, -F::one()),
                (
                    split_form.a_spread,
                    F::from((1u64 << 52) + (1u64 << 42) + (1u64 << 14)),
                ),
                (
                    split_form.b_spread,
                    F::from(1u64 + (1u64 << 54) + (1u64 << 26)),
                ),
                (
                    split_form.c_spread,
                    F::from(1u64 + (1u64 << 36) + (1u64 << 10)),
                ),
                (
                    split_form.d_spread,
                    F::from(1u64 + (1u64 << 38) + (1u64 << 28)),
                ),
            ],
            F::zero(),
            F::zero(),
        );
    }

    let tmp = R.into_repr();
    let R_u64 = tmp.as_ref();
    let R_u64 = R_u64[0];

    let mut Reven_hi = 0u64;
    let mut Reven_low = 0u64;
    let mut Rodd_hi = 0u64;
    let mut Rodd_low = 0u64;

    let mut tmp = R_u64;
    // low
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Reven_low += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Rodd_low += 1 << i;
        }
    }
    // hi
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Reven_hi += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Rodd_hi += 1 << i;
        }
    }

    let Reven_hi_sign = if Reven_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Reven_low_sign = if Reven_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Rodd_hi_sign = if Rodd_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Rodd_low_sign = if Rodd_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };

    let Reven_hi = cs.alloc(F::from(Reven_hi));
    let Reven_low = cs.alloc(F::from(Reven_low));
    let Rodd_hi = cs.alloc(F::from(Rodd_hi));
    let Rodd_low = cs.alloc(F::from(Rodd_low));

    let spread16_index = cs.get_table_index("spread_16bits_14bits".to_string());
    assert!(spread16_index != 0);

    let Reven_hi_spread = cs.read_from_table(spread16_index, vec![Reven_hi, Reven_hi_sign])?;
    let Reven_low_spread = cs.read_from_table(spread16_index, vec![Reven_low, Reven_low_sign])?;
    let Rodd_hi_spread = cs.read_from_table(spread16_index, vec![Rodd_hi, Rodd_hi_sign])?;
    let Rodd_low_spread = cs.read_from_table(spread16_index, vec![Rodd_low, Rodd_low_sign])?;

    // R' = 2^{32}Reven_H' + Reven_L' + 2^{32}2Rodd_H' + 2Rodd_L'
    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (Reven_hi_spread[0], F::from(1u64 << 32)),
                (Reven_low_spread[0], F::one()),
                (Rodd_hi_spread[0], F::from(1u64 << 33)),
                (Rodd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
            vec![(Rvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Rvar, -F::one()),
                (Reven_hi_spread[0], F::from(1u64 << 32)),
                (Reven_low_spread[0], F::one()),
                (Rodd_hi_spread[0], F::from(1u64 << 33)),
                (Rodd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
        );
    }

    // hi, low
    Ok((Reven_hi, Reven_low))
}

/// Maj(A, B, C)
fn sha256_Maj<F: Field>(
    cs: &mut Composer<F>,
    wordA: &Sha256Word,
    wordB: &Sha256Word,
    wordC: &Sha256Word,
) -> Result<(Variable, Variable), Error> {
    let Ah_spread_value = cs.get_assignment(wordA.hvar_spread);
    let Al_spread_value = cs.get_assignment(wordA.lvar_spread);
    let Bh_spread_value = cs.get_assignment(wordB.hvar_spread);
    let Bl_spread_value = cs.get_assignment(wordB.lvar_spread);
    let Ch_spread_value = cs.get_assignment(wordC.hvar_spread);
    let Cl_spread_value = cs.get_assignment(wordC.lvar_spread);

    // M' =  A' + B' + C'
    let tmp = Ah_spread_value * F::from(1u64 << 32)
        + Bh_spread_value * F::from(1u64 << 32)
        + Bl_spread_value;
    let M = tmp + Ch_spread_value * F::from(1u64 << 32) + Cl_spread_value + Al_spread_value;
    assert!(M.into_repr().num_bits() as usize <= 64);

    let tmp_var = cs.alloc(tmp);
    let M_var = cs.alloc(M);

    // cal Meven_H, Meven_L, Modd_H, Modd_L
    let tmp = M.into_repr();
    let M_u64 = tmp.as_ref();
    let M_u64 = M_u64[0];

    let mut Meven_hi = 0u64;
    let mut Meven_low = 0u64;
    let mut Modd_hi = 0u64;
    let mut Modd_low = 0u64;

    let mut tmp = M_u64;
    // low
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Meven_low += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Modd_low += 1 << i;
        }
    }
    // hi
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Meven_hi += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Modd_hi += 1 << i;
        }
    }

    let Meven_hi_sign = if Meven_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Meven_low_sign = if Meven_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Modd_hi_sign = if Modd_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Modd_low_sign = if Modd_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };

    let Meven_hi = cs.alloc(F::from(Meven_hi));
    let Meven_low = cs.alloc(F::from(Meven_low));
    let Modd_hi = cs.alloc(F::from(Modd_hi));
    let Modd_low = cs.alloc(F::from(Modd_low));

    let spread16_index = cs.get_table_index("spread_16bits_14bits".to_string());
    assert!(spread16_index != 0);

    let Meven_hi_spread = cs.read_from_table(spread16_index, vec![Meven_hi, Meven_hi_sign])?;
    let Meven_low_spread = cs.read_from_table(spread16_index, vec![Meven_low, Meven_low_sign])?;
    let Modd_hi_spread = cs.read_from_table(spread16_index, vec![Modd_hi, Modd_hi_sign])?;
    let Modd_low_spread = cs.read_from_table(spread16_index, vec![Modd_low, Modd_low_sign])?;

    if cs.program_width == 4 {
        // 2^{32}Meven_H' + Meven_L' + 2^{32}2Modd_H' + 2Modd_L' = (M')next
        // M' = 2^{32}C_H' + C_L' + A_L' + (tmp)next
        // tmp = 2^{32}B_H' + B_L' + 2^{32}A_H'
        cs.fully_customizable_poly_gates(
            vec![
                vec![
                    (Meven_hi_spread[0], F::from(1u64 << 32)),
                    (Meven_low_spread[0], F::one()),
                    (Modd_hi_spread[0], F::from(1u64 << 33)),
                    (Modd_low_spread[0], F::from(2_u64)),
                ],
                vec![
                    (M_var, -F::one()),
                    (wordC.hvar_spread, F::from(1u64 << 32)),
                    (wordC.lvar_spread, F::one()),
                    (wordA.lvar_spread, F::one()),
                ],
                vec![
                    (tmp_var, -F::one()),
                    (wordA.hvar_spread, F::from(1u64 << 32)),
                    (wordB.hvar_spread, F::from(1u64 << 32)),
                    (wordB.lvar_spread, F::one()),
                ],
            ],
            vec![F::zero(), F::zero(), F::zero()],
            vec![F::zero(), F::zero(), F::zero()],
            vec![-F::one(), F::one(), F::zero()],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (tmp_var, -F::one()),
                (wordA.hvar_spread, F::from(1u64 << 32)),
                (wordB.hvar_spread, F::from(1u64 << 32)),
                (wordB.lvar_spread, F::one()),
            ],
            F::zero(),
            F::zero(),
        );
        cs.poly_gate(
            vec![
                (M_var, -F::one()),
                (wordC.hvar_spread, F::from(1u64 << 32)),
                (wordC.lvar_spread, F::one()),
                (wordA.lvar_spread, F::one()),
                (tmp_var, F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        // M' = 2^{32}Meven_H' + Meven_L' + 2^{32}2Modd_H' + 2Modd_L'
        cs.poly_gate(
            vec![
                (M_var, -F::one()),
                (Meven_hi_spread[0], F::from(1u64 << 32)),
                (Meven_low_spread[0], F::one()),
                (Modd_hi_spread[0], F::from(1u64 << 33)),
                (Modd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
        );
    }

    // hi, low
    Ok((Modd_hi, Modd_low))
}

/// Ch(E, F, G)
fn sha256_Ch<F: Field>(
    cs: &mut Composer<F>,
    wordE: &Sha256Word,
    wordF: &Sha256Word,
    wordG: &Sha256Word,
) -> Result<Variable, Error> {
    let Eh_spread_value = cs.get_assignment(wordE.hvar_spread);
    let El_spread_value = cs.get_assignment(wordE.lvar_spread);
    let Fh_spread_value = cs.get_assignment(wordF.hvar_spread);
    let Fl_spread_value = cs.get_assignment(wordF.lvar_spread);
    let Gh_spread_value = cs.get_assignment(wordG.hvar_spread);
    let Gl_spread_value = cs.get_assignment(wordG.lvar_spread);

    // P' =  E' + F'
    let P = Eh_spread_value * F::from(1u64 << 32)
        + El_spread_value
        + Fh_spread_value * F::from(1u64 << 32)
        + Fl_spread_value;
    assert!(P.into_repr().num_bits() as usize <= 64);

    let Pvar = cs.alloc(P);

    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (wordE.hvar_spread, F::from(1u64 << 32)),
                (wordE.lvar_spread, F::one()),
                (wordF.hvar_spread, F::from(1u64 << 32)),
                (wordF.lvar_spread, F::one()),
            ],
            F::zero(),
            F::zero(),
            vec![(Pvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Pvar, -F::one()),
                (wordE.hvar_spread, F::from(1u64 << 32)),
                (wordE.lvar_spread, F::one()),
                (wordF.hvar_spread, F::from(1u64 << 32)),
                (wordF.lvar_spread, F::one()),
            ],
            F::zero(),
            F::zero(),
        );
    }

    // cal Peven_H, Peven_L, Podd_H, Podd_L
    let tmp = P.into_repr();
    let P_u64 = tmp.as_ref();
    let P_u64 = P_u64[0];

    let mut Peven_hi = 0u64;
    let mut Peven_low = 0u64;
    let mut Podd_hi = 0u64;
    let mut Podd_low = 0u64;

    let mut tmp = P_u64;
    // low
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Peven_low += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Podd_low += 1 << i;
        }
    }
    // hi
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Peven_hi += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Podd_hi += 1 << i;
        }
    }

    let Peven_hi_sign = if Peven_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Peven_low_sign = if Peven_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Podd_hi_sign = if Podd_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Podd_low_sign = if Podd_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };

    let Podd_hi_fvalue = F::from(Podd_hi);
    let Podd_low_fvalue = F::from(Podd_low);

    let Peven_hi = cs.alloc(F::from(Peven_hi));
    let Peven_low = cs.alloc(F::from(Peven_low));
    let Podd_hi = cs.alloc(F::from(Podd_hi));
    let Podd_low = cs.alloc(F::from(Podd_low));

    let spread16_index = cs.get_table_index("spread_16bits_14bits".to_string());
    assert!(spread16_index != 0);

    let Peven_hi_spread = cs.read_from_table(spread16_index, vec![Peven_hi, Peven_hi_sign])?;
    let Peven_low_spread = cs.read_from_table(spread16_index, vec![Peven_low, Peven_low_sign])?;
    let Podd_hi_spread = cs.read_from_table(spread16_index, vec![Podd_hi, Podd_hi_sign])?;
    let Podd_low_spread = cs.read_from_table(spread16_index, vec![Podd_low, Podd_low_sign])?;

    // P' = 2^{32}Peven_H' + Peven_L' + 2^{32}2Podd_H' + 2Podd_L'
    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (Peven_hi_spread[0], F::from(1u64 << 32)),
                (Peven_low_spread[0], F::one()),
                (Podd_hi_spread[0], F::from(1u64 << 33)),
                (Podd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
            vec![(Pvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Pvar, -F::one()),
                (Peven_hi_spread[0], F::from(1u64 << 32)),
                (Peven_low_spread[0], F::one()),
                (Podd_hi_spread[0], F::from(1u64 << 33)),
                (Podd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
        );
    }

    let eh = cs.get_assignment(Peven_hi_spread[0]);
    let el = cs.get_assignment(Peven_low_spread[0]);
    let oh = cs.get_assignment(Podd_hi_spread[0]);
    let ol = cs.get_assignment(Podd_low_spread[0]);
    assert_eq!(
        P - eh * F::from(1u64 << 32) - el - oh * F::from(1u64 << 33) - ol * F::from(2_u64),
        F::zero()
    );

    // Q' = ¬E' + G' (where ¬E' = 0101...0101 - E')
    let mut const_0101 = 1u64;
    for _ in 1..32 {
        const_0101 <<= 2;
        const_0101 += 1;
    }
    let Q = F::from(const_0101) - Eh_spread_value * F::from(1u64 << 32) - El_spread_value
        + Gh_spread_value * F::from(1u64 << 32)
        + Gl_spread_value;
    assert!(Q.into_repr().num_bits() as usize <= 64);

    let Qvar = cs.alloc(Q);

    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (wordE.hvar_spread, -F::from(1u64 << 32)),
                (wordE.lvar_spread, -F::one()),
                (wordG.hvar_spread, F::from(1u64 << 32)),
                (wordG.lvar_spread, F::one()),
            ],
            F::zero(),
            F::from(const_0101),
            vec![(Qvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Qvar, -F::one()),
                (wordE.hvar_spread, -F::from(1u64 << 32)),
                (wordE.lvar_spread, -F::one()),
                (wordG.hvar_spread, F::from(1u64 << 32)),
                (wordG.lvar_spread, F::one()),
            ],
            F::zero(),
            F::from(const_0101),
        );
    }

    // cal Qeven_H, Qeven_L, Qodd_H, Qodd_L
    let tmp = Q.into_repr();
    let Q_u64 = tmp.as_ref();
    let Q_u64 = Q_u64[0];

    let mut Qeven_hi = 0u64;
    let mut Qeven_low = 0u64;
    let mut Qodd_hi = 0u64;
    let mut Qodd_low = 0u64;

    let mut tmp = Q_u64;
    // low
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Qeven_low += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Qodd_low += 1 << i;
        }
    }
    // hi
    for i in 0..16_u64 {
        // first even
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Qeven_hi += 1 << i;
        }

        // then odd
        let this_bit = tmp % 2;
        tmp >>= 1;

        if this_bit == 1 {
            Qodd_hi += 1 << i;
        }
    }

    let Qeven_hi_sign = if Qeven_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Qeven_low_sign = if Qeven_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Qodd_hi_sign = if Qodd_hi < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };
    let Qodd_low_sign = if Qodd_low < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };

    let Qodd_hi_fvalue = F::from(Qodd_hi);
    let Qodd_low_fvalue = F::from(Qodd_low);

    let Qeven_hi = cs.alloc(F::from(Qeven_hi));
    let Qeven_low = cs.alloc(F::from(Qeven_low));
    let Qodd_hi = cs.alloc(F::from(Qodd_hi));
    let Qodd_low = cs.alloc(F::from(Qodd_low));

    let Qeven_hi_spread = cs.read_from_table(spread16_index, vec![Qeven_hi, Qeven_hi_sign])?;
    let Qeven_low_spread = cs.read_from_table(spread16_index, vec![Qeven_low, Qeven_low_sign])?;
    let Qodd_hi_spread = cs.read_from_table(spread16_index, vec![Qodd_hi, Qodd_hi_sign])?;
    let Qodd_low_spread = cs.read_from_table(spread16_index, vec![Qodd_low, Qodd_low_sign])?;

    // Q' = 2^{32}Qeven_H' + Qeven_L' + 2^{32}2Qodd_H' + 2Qodd_L'
    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (Qeven_hi_spread[0], F::from(1u64 << 32)),
                (Qeven_low_spread[0], F::one()),
                (Qodd_hi_spread[0], F::from(1u64 << 33)),
                (Qodd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
            vec![(Qvar, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Qvar, -F::one()),
                (Qeven_hi_spread[0], F::from(1u64 << 32)),
                (Qeven_low_spread[0], F::one()),
                (Qodd_hi_spread[0], F::from(1u64 << 33)),
                (Qodd_low_spread[0], F::from(2_u64)),
            ],
            F::zero(),
            F::zero(),
        );
    }

    // Ch = 2^{16}Podd_H + Podd_L + 2^{16}Qodd_H + Qodd_L
    let Ch = Podd_hi_fvalue * F::from(1u64 << 16)
        + Podd_low_fvalue
        + Qodd_hi_fvalue * F::from(1u64 << 16)
        + Qodd_low_fvalue;
    assert!(Ch.into_repr().num_bits() as usize <= 32);

    let Ch_var = cs.alloc(Ch);

    if cs.program_width == 4 {
        cs.poly_gate_with_next(
            vec![
                (Podd_hi, F::from(1u64 << 16)),
                (Podd_low, F::one()),
                (Qodd_hi, F::from(1u64 << 16)),
                (Qodd_low, F::one()),
            ],
            F::zero(),
            F::zero(),
            vec![(Ch_var, -F::one())],
        );
    } else if cs.program_width >= 5 {
        cs.poly_gate(
            vec![
                (Ch_var, -F::one()),
                (Podd_hi, F::from(1u64 << 16)),
                (Podd_low, F::one()),
                (Qodd_hi, F::from(1u64 << 16)),
                (Qodd_low, F::one()),
            ],
            F::zero(),
            F::zero(),
        );
    }

    Ok(Ch_var)
}

///output n selectors, only out[num_value] = 1, others = 0
pub fn num_to_selectors<F: Field>(cs: &mut Composer<F>, num: Variable, n: usize) -> Vec<Variable> {
    //convert to u64
    let num_uint: Vec<u64> = cs.get_assignment(num).into_repr().as_ref().into();
    assert_eq!(num_uint[1], 0);
    assert_eq!(num_uint[2], 0);
    assert_eq!(num_uint[3], 0);
    assert!(num_uint[0] < n as u64);

    let mut out = Vec::new();

    for i in 0..n {
        let out_i = if i == (num_uint[0] as usize) {
            //the selector eq to 1
            cs.alloc(F::one())
        } else {
            cs.alloc(F::zero())
        };

        cs.enforce_bool(out_i);
        out.push(out_i);

        //(num - CONSTi) * out == 0
        cs.poly_gate(
            vec![(num, F::zero()), (out_i, -F::from(i as u128))],
            F::one(),
            F::zero(),
        );
    }

    //all out sum === 1
    let mut tmp_sum = out[0];
    for i in 1..n {
        tmp_sum = cs.add(tmp_sum, out[i]);
    }

    cs.enforce_constant(tmp_sum, F::one());

    out
}

///choose 1 from n, with n selectors(MUST and only one is 1)
pub fn mux1_from_selectors<F: Field>(
    cs: &mut Composer<F>,
    var_n: &[Variable],
    selectors: &[Variable],
) -> Variable {
    assert_eq!(var_n.len(), selectors.len());

    let mut tmp = Composer::<F>::null();
    let mut tmp_out = Composer::<F>::null();

    for i in 0..selectors.len() {
        let tmp_out_value: F =
            cs.get_assignment(selectors[i]) * cs.get_assignment(var_n[i]) + cs.get_assignment(tmp);
        tmp_out = cs.alloc(tmp_out_value);

        // var[i] * selectors[i] + tmp = tmp_out
        cs.poly_gate(
            vec![
                (selectors[i], F::zero()),
                (var_n[i], F::zero()),
                (tmp, F::one()),
                (tmp_out, -F::one()),
            ],
            F::one(),
            F::zero(),
        );

        tmp = tmp_out;
    }

    tmp_out
}

/// sha256: compress some full 512bits messages. msg_len: block_num of message.
/// return 8 * 32bits
pub fn sha256_no_padding_words_var<F: Field>(
    cs: &mut Composer<F>,
    chunk_messages: &[Sha256Word],
    msg_len: Variable,
    block_num_limit: usize,
) -> Result<Vec<Variable>, Error> {
    //convert to u64
    let msg_len_uint: Vec<u64> = cs.get_assignment(msg_len).into_repr().as_ref().into();
    assert_eq!(msg_len_uint[1], 0);
    assert_eq!(msg_len_uint[2], 0);
    assert_eq!(msg_len_uint[3], 0);
    assert!(msg_len_uint[0] <= block_num_limit as u64);
    assert!(msg_len_uint[0] > 0);
    assert_eq!(chunk_messages.len() as u64, 16 * block_num_limit as u64);

    let _ = cs.add_table(Table::spread_table(2));
    let _ = cs.add_table(Table::spread_table(3));

    let _ = cs.add_table(Table::spread_table_2in1(5, 4));
    let _ = cs.add_table(Table::spread_table_2in1(13, 11));
    let _ = cs.add_table(Table::spread_table_2in1(10, 9));
    let _ = cs.add_table(Table::spread_table_2in1(7, 6));
    let _ = cs.add_table(Table::spread_table_2in1(16, 14));

    let mut hashs = vec![];

    let mut init_hash = vec![];
    for i in 0..8 {
        let value = F::from(BigUint::parse_bytes(INIT_SHA256HASH[i].as_bytes(), 16).unwrap());
        let var = cs.alloc(value);
        let initword = Sha256Word::new_from_32bits_var(cs, var)?;
        cs.enforce_constant(var, value);
        init_hash.push(initword);
    }
    hashs.push(init_hash);

    // main
    for i in 0..block_num_limit {
        let reshash =
            sha256_chunk_words_var(cs, &chunk_messages[(16 * i)..(16 * i + 16)], &hashs[i])?;
        hashs.push(reshash);
    }

    // selectors start from 0. so need -1
    let out_index = cs.alloc(F::from(msg_len_uint[0] - 1));
    cs.poly_gate(
        vec![(msg_len, -F::one()), (out_index, F::one())],
        F::zero(),
        F::one(),
    );
    let selectors = num_to_selectors(cs, out_index, block_num_limit);

    let mut out_hash = vec![];
    for i in 0..8 {
        let mut tmp = vec![];
        for j in 0..block_num_limit {
            tmp.push(hashs[j + 1][i].var);
        }

        out_hash.push(mux1_from_selectors(cs, &tmp, &selectors));
    }

    Ok(out_hash)
}

/// sha256: compress fixed_length full 512bits messages.
/// return 8 * 32bits
pub fn sha256_no_padding_words_var_fixed_length<F: Field>(
    cs: &mut Composer<F>,
    chunk_messages: &[Sha256Word],
    block_num: usize,
) -> Result<Vec<Variable>, Error> {
    assert_eq!(chunk_messages.len() as u64, 16 * block_num as u64);

    let _ = cs.add_table(Table::spread_table(2));
    let _ = cs.add_table(Table::spread_table(3));

    let _ = cs.add_table(Table::spread_table_2in1(5, 4));
    let _ = cs.add_table(Table::spread_table_2in1(13, 11));
    let _ = cs.add_table(Table::spread_table_2in1(10, 9));
    let _ = cs.add_table(Table::spread_table_2in1(7, 6));
    let _ = cs.add_table(Table::spread_table_2in1(16, 14));

    let mut hashs = vec![];

    let mut init_hash = vec![];
    for i in 0..8 {
        let value = F::from(BigUint::parse_bytes(INIT_SHA256HASH[i].as_bytes(), 16).unwrap());
        let var = cs.alloc(value);
        let initword = Sha256Word::new_from_32bits_var(cs, var)?;
        cs.enforce_constant(var, value);
        init_hash.push(initword);
    }
    hashs.push(init_hash);

    // main
    for i in 0..block_num {
        let reshash =
            sha256_chunk_words_var(cs, &chunk_messages[(16 * i)..(16 * i + 16)], &hashs[i])?;
        hashs.push(reshash);
    }

    let mut out_hash = vec![];
    for i in 0..8 {
        out_hash.push(hashs[block_num][i].var);
    }

    Ok(out_hash)
}

/// return 2 * 128bits
pub fn sha256_collect_8_outputs_to_2_128bits<F: Field>(
    cs: &mut Composer<F>,
    sha256_hash: &[Variable],
) -> Result<Vec<Variable>, Error> {
    assert_eq!(sha256_hash.len(), 8);

    let out_hash_values = cs.get_assignments(sha256_hash);
    let tmp0 = out_hash_values[0] * F::from(1u128 << 96)
        + out_hash_values[1] * F::from(1u128 << 64)
        + out_hash_values[2] * F::from(1u128 << 32)
        + out_hash_values[3];
    let tmp0_var = cs.alloc(tmp0);
    cs.poly_gate(
        vec![
            (tmp0_var, -F::one()),
            (sha256_hash[0], F::from(1u128 << 96)),
            (sha256_hash[1], F::from(1u128 << 64)),
            (sha256_hash[2], F::from(1u128 << 32)),
            (sha256_hash[3], F::one()),
        ],
        F::zero(),
        F::zero(),
    );

    let tmp1 = out_hash_values[4] * F::from(1u128 << 96)
        + out_hash_values[5] * F::from(1u128 << 64)
        + out_hash_values[6] * F::from(1u128 << 32)
        + out_hash_values[7];
    let tmp1_var = cs.alloc(tmp1);
    cs.poly_gate(
        vec![
            (tmp1_var, -F::one()),
            (sha256_hash[4], F::from(1u128 << 96)),
            (sha256_hash[5], F::from(1u128 << 64)),
            (sha256_hash[6], F::from(1u128 << 32)),
            (sha256_hash[7], F::one()),
        ],
        F::zero(),
        F::zero(),
    );

    Ok(vec![tmp0_var, tmp1_var])
}

/// return 253bits (dump 3bits)
pub fn sha256_collect_8_outputs_to_field<F: Field>(
    cs: &mut Composer<F>,
    sha256_hash: &[Variable],
) -> Result<Variable, Error> {
    assert_eq!(sha256_hash.len(), 8);

    let out_hash_values = cs.get_assignments(sha256_hash);

    //convert to u64
    let out_hash_0_uint: Vec<u64> = out_hash_values[0].into_repr().as_ref().into();
    let out_hash_0_u64 = out_hash_0_uint[0];
    let top_value_u64 = out_hash_0_u64 % (1u64 << 29);
    let top_remainder_u64 = out_hash_0_u64 / (1u64 << 29);
    let top_value = F::from(top_value_u64);
    let top_remainder = F::from(top_remainder_u64);

    let top_var = cs.alloc(top_value);
    let remainder_var = cs.alloc(top_remainder);
    cs.poly_gate(
        vec![
            (sha256_hash[0], -F::one()),
            (top_var, F::one()),
            (remainder_var, F::from(1u64 << 29)),
        ],
        F::zero(),
        F::zero(),
    );

    // range constraint
    let top_low_u64 = top_value_u64 % (1u64 << 16);
    let top_hi_u64 = top_value_u64 / (1u64 << 16); // 13 bits
    let top_hvar = cs.alloc(F::from(top_hi_u64));
    let top_lvar = cs.alloc(F::from(top_low_u64));

    let spread16_index = cs.get_table_index("spread_16bits_14bits".to_string());
    assert!(spread16_index != 0);
    let spread14_index = spread16_index;

    let top_low_sign = if top_low_u64 < (1u64 << 14) {
        cs.alloc(F::zero())
    } else {
        cs.alloc(F::one())
    };

    let _ = cs.read_from_table(spread14_index, vec![top_hvar, Composer::<F>::null()])?;
    let _ = cs.read_from_table(spread16_index, vec![top_lvar, top_low_sign])?;

    let spread3_index = cs.get_table_index("spread_3bits".to_string());
    assert!(spread3_index != 0);
    let _ = cs.read_from_table(spread3_index, vec![remainder_var])?;

    cs.poly_gate(
        vec![
            (top_var, -F::one()),
            (top_lvar, F::one()),
            (top_hvar, F::from(1u64 << 16)),
        ],
        F::zero(),
        F::zero(),
    );

    let tmp0 = top_value * F::from(1u128 << 96)
        + out_hash_values[1] * F::from(1u128 << 64)
        + out_hash_values[2] * F::from(1u128 << 32)
        + out_hash_values[3];
    let tmp0_var = cs.alloc(tmp0);
    cs.poly_gate(
        vec![
            (tmp0_var, -F::one()),
            (top_var, F::from(1u128 << 96)),
            (sha256_hash[1], F::from(1u128 << 64)),
            (sha256_hash[2], F::from(1u128 << 32)),
            (sha256_hash[3], F::one()),
        ],
        F::zero(),
        F::zero(),
    );

    let tmp1 = out_hash_values[4] * F::from(1u128 << 96)
        + out_hash_values[5] * F::from(1u128 << 64)
        + out_hash_values[6] * F::from(1u128 << 32)
        + out_hash_values[7];
    let tmp1_var = cs.alloc(tmp1);
    cs.poly_gate(
        vec![
            (tmp1_var, -F::one()),
            (sha256_hash[4], F::from(1u128 << 96)),
            (sha256_hash[5], F::from(1u128 << 64)),
            (sha256_hash[6], F::from(1u128 << 32)),
            (sha256_hash[7], F::one()),
        ],
        F::zero(),
        F::zero(),
    );

    let out = tmp0 * F::from(1u128 << 64) * F::from(1u128 << 64) + tmp1;
    let out_var = cs.alloc(out);
    cs.poly_gate(
        vec![
            (out_var, -F::one()),
            (tmp0_var, F::from(1u128 << 64) * F::from(1u128 << 64)),
            (tmp1_var, F::one()),
        ],
        F::zero(),
        F::zero(),
    );

    Ok(out_var)
}

#[cfg(test)]
mod tests {
    #![allow(non_snake_case)]
    use ark_bn254::Fr;
    use ark_ff::One;
    use ark_std::test_rng;

    use crate::composer::{Composer, Table};
    use crate::kzg10::PCKey;
    use crate::prover::Prover;
    use crate::verifier::Verifier;
    use crate::GeneralEvaluationDomain;

    use super::*;
    use ark_std::time::Instant; // timer

    #[test]
    fn spread_table() -> Result<(), Error> {
        Table::<Fr>::spread_table(3);

        let mut cs = {
            let mut cs = Composer::new(5, false);

            let table_index = cs.add_table(Table::xor_table(4));
            let xtt = cs.alloc(Fr::from(1));
            let ytt = cs.alloc(Fr::from(2));
            let ztt = cs.read_from_table(table_index, vec![xtt, ytt])?;
            cs.enforce_constant(ztt[0], Fr::from(3));

            let table_index = cs.add_table(Table::spread_table(5));
            let stt = cs.alloc(Fr::from(7));
            let ztt = cs.read_from_table(table_index, vec![stt])?;
            cs.enforce_constant(ztt[0], Fr::from(21));

            cs
        };

        test_prove_verify(&mut cs)?;

        Ok(())
    }

    fn test_prove_verify(cs: &mut Composer<Fr>) -> Result<(), Error> {
        println!();
        let public_input = cs.compute_public_input();
        println!("cs.size() {}", cs.size());
        println!("cs.table_size() {}", cs.table_size());
        println!("cs.sorted_size() {}", cs.sorted_size());

        let rng = &mut test_rng();

        println!("time start:");
        let start = Instant::now();
        println!("compute_prover_key...");
        let pk = cs.compute_prover_key::<GeneralEvaluationDomain<Fr>>()?;
        println!("compute_prover_key...done");
        let pckey = PCKey::<ark_bn254::Bn254>::setup(pk.domain_size() + pk.program_width + 6, rng);
        let mut prover = Prover::<Fr, GeneralEvaluationDomain<Fr>, ark_bn254::Bn254>::new(pk);

        println!("init_comms...");
        let verifier_comms = prover.init_comms(&pckey);
        println!("init_comms...done");
        println!("time cost: {:?} ms", start.elapsed().as_millis()); // ms
        let mut verifier = Verifier::new(&prover, &public_input, &verifier_comms);

        println!("prove start:");
        let start = Instant::now();
        let proof = prover.prove(cs, &pckey, rng)?;
        println!("prove time cost: {:?} ms", start.elapsed().as_millis()); // ms

        let sha256_of_srs = pckey.sha256_of_srs();
        println!("verify start:");
        let start = Instant::now();
        let res = verifier.verify(&pckey.vk, &proof, &sha256_of_srs);
        println!("verify result: {}", res);
        println!("verify time cost: {:?} ms", start.elapsed().as_millis()); // ms

        Ok(())
    }

    #[test]
    fn sha256_inner_func() -> Result<(), Error> {
        let mut cs = {
            let mut cs = Composer::new(4, true);

            let _ = cs.add_table(Table::spread_table(3));
            let _ = cs.add_table(Table::spread_table(2));
            let _ = cs.add_table(Table::spread_table_2in1(5, 4));
            let _ = cs.add_table(Table::spread_table_2in1(13, 11));
            let _ = cs.add_table(Table::spread_table_2in1(10, 9));
            let _ = cs.add_table(Table::spread_table_2in1(7, 6));
            let spread16_index = cs.add_table(Table::spread_table_2in1(16, 14));

            let w = cs.alloc(Fr::from(65535_u64));
            let onevar = cs.alloc(Fr::one());
            let w_spread = cs.read_from_table(spread16_index, vec![w, onevar])?;

            let value = cs.get_assignment(w_spread[0]);
            println!("value{}", value);
            let var = cs.alloc(value);
            let word = Sha256Word::new_from_32bits_var(&mut cs, var)?;

            let (hi, low) = sha256_sigma_0(&mut cs, &word)?;
            println!("hi{}", cs.get_assignment(hi));
            println!("low{}", cs.get_assignment(low));

            let (hi, low) = sha256_sigma_1(&mut cs, &word)?;
            println!("hi{}", cs.get_assignment(hi));
            println!("low{}", cs.get_assignment(low));

            let (hi, low) = sha256_sum_0(&mut cs, &word)?;
            println!("sum hi{}", cs.get_assignment(hi));
            println!("low{}", cs.get_assignment(low));

            let (hi, low) = sha256_sum_1(&mut cs, &word)?;
            println!("sum hi{}", cs.get_assignment(hi));
            println!("low{}", cs.get_assignment(low));

            let var2 = cs.alloc(Fr::from(65535u64 << 16));
            let var3 = cs.alloc(Fr::from((1u64 << 32) - 1));
            let word2 = Sha256Word::new_from_32bits_var(&mut cs, var2)?;
            let word3 = Sha256Word::new_from_32bits_var(&mut cs, var3)?;

            let (hi, low) = sha256_Maj(&mut cs, &word, &word2, &word3)?;
            println!("maj hi{}", cs.get_assignment(hi));
            println!("low{}", cs.get_assignment(low));

            let ch = sha256_Ch(&mut cs, &word, &word2, &word3)?;
            println!("ch {}", cs.get_assignment(ch));

            cs
        };

        test_prove_verify(&mut cs)?;

        Ok(())
    }

    #[test]
    fn sha256_1_chars() -> Result<(), Error> {
        // abc (padding to 512bits)
        let test_message = [
            "61626380", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000",
            "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000",
            "00000000", "00000018",
        ];

        let mut cs = {
            let mut cs = Composer::new(4, true);

            let _ = cs.add_table(Table::spread_table(3));
            let _ = cs.add_table(Table::spread_table(2));
            let _ = cs.add_table(Table::spread_table(8));

            let _ = cs.add_table(Table::spread_table_2in1(5, 4));
            let _ = cs.add_table(Table::spread_table_2in1(13, 11));
            let _ = cs.add_table(Table::spread_table_2in1(10, 9));
            let _ = cs.add_table(Table::spread_table_2in1(7, 6));
            let _ = cs.add_table(Table::spread_table_2in1(16, 14));

            let mut words = vec![];
            for elem in test_message {
                let mut value = BigUint::parse_bytes(elem.as_bytes(), 16).unwrap();
                let char4 = &value % (1u64 << 8);
                value >>= 8;
                let char3 = &value % (1u64 << 8);
                value >>= 8;
                let char2 = &value % (1u64 << 8);
                value >>= 8;
                let char1 = &value % (1u64 << 8);
                let char1 = cs.alloc(Fr::from(char1));
                let char2 = cs.alloc(Fr::from(char2));
                let char3 = cs.alloc(Fr::from(char3));
                let char4 = cs.alloc(Fr::from(char4));
                let word = Sha256Word::new_from_8bits(&mut cs, char1, char2, char3, char4)?;
                words.push(word);
            }
            let mut init_hash = vec![];
            for i in 0..8 {
                let value =
                    Fr::from(BigUint::parse_bytes(INIT_SHA256HASH[i].as_bytes(), 16).unwrap());
                let var = cs.alloc(value);
                let initword = Sha256Word::new_from_32bits_var(&mut cs, var)?;
                cs.enforce_constant(initword.var, value);
                init_hash.push(initword);
            }
            let reshash = sha256_chunk_words_var(&mut cs, &words, &init_hash)?;

            for elem in &reshash {
                let value = cs.get_assignment(elem.var);
                println!("{}", value);
            }

            cs
        };

        test_prove_verify(&mut cs)?;

        Ok(())
    }

    #[test]
    fn sha256_chars() -> Result<(), Error> {
        // abc (padding to 512bits)
        let test_message = [
            "61626380", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000",
            "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000",
            "00000000", "00000018",
        ];
        // test_message padding
        let test_message_extra = [
            "80000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000",
            "00000000", "00000000", "00000000", "00000000", "00000000", "00000000", "00000000",
            "00000000", "00000200",
        ];

        let mut cs = {
            let mut cs = Composer::new(5, false);
            let block_num_limit = 32;
            let msg_len = cs.alloc(Fr::from(1));

            let _ = cs.add_table(Table::spread_table(8));

            let mut words = vec![];
            for _ in 0..block_num_limit / 2 {
                for elem in test_message {
                    let mut value = BigUint::parse_bytes(elem.as_bytes(), 16).unwrap();
                    let char4 = &value % (1u64 << 8);
                    value >>= 8;
                    let char3 = &value % (1u64 << 8);
                    value >>= 8;
                    let char2 = &value % (1u64 << 8);
                    value >>= 8;
                    let char1 = &value % (1u64 << 8);
                    let char1 = cs.alloc(Fr::from(char1));
                    let char2 = cs.alloc(Fr::from(char2));
                    let char3 = cs.alloc(Fr::from(char3));
                    let char4 = cs.alloc(Fr::from(char4));
                    let word = Sha256Word::new_from_8bits(&mut cs, char1, char2, char3, char4)?;
                    words.push(word);
                }

                for elem in test_message_extra {
                    let mut value = BigUint::parse_bytes(elem.as_bytes(), 16).unwrap();
                    let char4 = &value % (1u64 << 8);
                    value >>= 8;
                    let char3 = &value % (1u64 << 8);
                    value >>= 8;
                    let char2 = &value % (1u64 << 8);
                    value >>= 8;
                    let char1 = &value % (1u64 << 8);
                    let char1 = cs.alloc(Fr::from(char1));
                    let char2 = cs.alloc(Fr::from(char2));
                    let char3 = cs.alloc(Fr::from(char3));
                    let char4 = cs.alloc(Fr::from(char4));
                    let word = Sha256Word::new_from_8bits(&mut cs, char1, char2, char3, char4)?;
                    words.push(word);
                }
            }

            let reshash = sha256_no_padding_words_var(&mut cs, &words, msg_len, block_num_limit)?;

            for elem in reshash {
                let value = cs.get_assignment(elem);
                println!("{}", value);
            }

            cs
        };

        test_prove_verify(&mut cs)?;

        Ok(())
    }
}
