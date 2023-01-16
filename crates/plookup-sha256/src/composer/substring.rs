use super::{Composer, Variable};
use crate::{Error, Field};
use ark_std::{format, vec::Vec};

impl<F: Field> Composer<F> {
    /// "b" is substring of "a". should be padding to the max len.
    /// l is the start index of "b" in "a".
    /// m is the actual length of "b".
    /// max_lens, b_max_lens must be a multiple of 32.
    /// "bits_location" from gen_bit_location_for_substr().
    /// If create multiple private-substring in the circuit, make sure 'mask's are different.
    pub fn add_substring_mask_poly_return_words(
        &mut self,
        a: &Vec<Variable>,
        b: &Vec<Variable>,
        a_bit_location: &Vec<Variable>,
        b_bit_location: &Vec<Variable>,
        mask: Variable,
        l: Variable,
        m: Variable,
        max_lens: usize,
        b_max_lens: usize,
    ) -> Result<(), Error> {
        assert_eq!(max_lens % 32, 0);
        assert_eq!(b_max_lens % 32, 0);
        assert!(self.program_width >= 5);
        if !self.switches.enable_private_substring {
            self.switches.enable_private_substring = true;
        }
        if !self.selectors.contains_key("q_substring_r") {
            let current_index = self.size();
            self.selectors
                .insert("q_substring_r".to_string(), vec![F::zero(); current_index]);
        }
        if !self.selectors.contains_key("q_substring") {
            let current_index = self.size();
            self.selectors
                .insert("q_substring".to_string(), vec![F::zero(); current_index]);
        }
        assert!(!self.is_finalized);

        assert_eq!(a.len(), max_lens);
        assert!(b.len() >= b_max_lens);
        let mut b = b.clone()[0..b_max_lens].to_vec();

        let l_value = self.get_assignment(l);
        let l_uint: Vec<u64> = l_value.into_repr().as_ref().into();
        assert_eq!(l_uint[1], 0);
        assert_eq!(l_uint[2], 0);
        assert_eq!(l_uint[3], 0);
        let l_uint = l_uint[0];
        let m_value = self.get_assignment(m);
        let m_uint: Vec<u64> = m_value.into_repr().as_ref().into();
        assert_eq!(m_uint[1], 0);
        assert_eq!(m_uint[2], 0);
        assert_eq!(m_uint[3], 0);
        let m_uint = m_uint[0];

        let r_value = self.get_assignment(mask);

        let mut comb = r_value;
        let mut mask_poly_b = vec![];
        let mut bit_location_b = b_bit_location.clone();

        let mut mask_poly_a = vec![];
        for _ in 0..l_uint {
            mask_poly_a.push(self.alloc(F::zero()));
        }

        for _ in 0..m_uint {
            mask_poly_b.push(self.alloc(comb));
            mask_poly_a.push(self.alloc(comb));
            comb *= r_value;
        }

        for _ in m_uint..b_max_lens as u64 {
            mask_poly_b.push(self.alloc(F::zero()));
        }

        let tmplen = mask_poly_a.len();
        for _ in tmplen..max_lens {
            mask_poly_a.push(self.alloc(F::zero()));
        }
        // padding b
        for _ in b_max_lens..max_lens {
            mask_poly_b.push(Composer::<F>::null());
            bit_location_b.push(Composer::<F>::null());
            b.push(Composer::<F>::null());
        }

        // prove ra and rb.
        // w0:bit_location. w1:bit_location. w2:mask_poly. w3: mask_r

        // must have this line at first
        let index = self.insert_gate(vec![
            Composer::<F>::null(),
            Composer::<F>::null(),
            Composer::<F>::null(),
            mask,
        ]);
        self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::one();

        let mut current_index = self.size();
        for i in 0..max_lens {
            let wires = vec![a_bit_location[i], a_bit_location[i], mask_poly_a[i], mask];

            let index = self.insert_gate(wires);
            assert_eq!(current_index, index);

            self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::one();
            if i == max_lens - 1 {
                self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::zero();
            }

            // enforce_bool
            self.selectors.get_mut("q_m").unwrap()[index] = F::one();
            self.selectors.get_mut("q_0").unwrap()[index] = -F::one();

            current_index += 1;
        }

        // must have this line at first
        let index = self.insert_gate(vec![
            Composer::<F>::null(),
            Composer::<F>::null(),
            Composer::<F>::null(),
            mask,
        ]);
        self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::one();

        let mut current_index = self.size();
        for i in 0..b_max_lens {
            let wires = vec![bit_location_b[i], bit_location_b[i], mask_poly_b[i], mask];

            let index = self.insert_gate(wires);
            assert_eq!(current_index, index);

            self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::one();
            if i == b_max_lens - 1 {
                self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::zero();
            }

            // enforce_bool
            self.selectors.get_mut("q_m").unwrap()[index] = F::one();
            self.selectors.get_mut("q_0").unwrap()[index] = -F::one();

            current_index += 1;
        }

        // prove substring
        // w0:mask_poly_a. w1:a. w2:mask_poly_b. w3:b.
        let mut current_index = self.size();
        for i in 0..max_lens {
            let wires = vec![mask_poly_a[i], a[i], mask_poly_b[i], b[i]];

            let index = self.insert_gate(wires);
            assert_eq!(current_index, index);

            self.selectors.get_mut(&format!("q_substring")).unwrap()[index] = F::one();

            current_index += 1;
        }

        Ok(())
    }

    /// generate "bits_location", 1 Variable represent 1 bit
    /// max_lens, b_max_lens must be a multiple of 32.
    pub fn gen_bit_location_for_substr(
        &mut self,
        l: Variable,
        m: Variable,
        max_lens: usize,
        b_max_lens: usize,
    ) -> Result<(Vec<Variable>, Vec<Variable>), Error> {
        assert_eq!(max_lens % 32, 0);
        assert_eq!(b_max_lens % 32, 0);
        assert!(self.program_width >= 5);

        let l_value = self.get_assignment(l);
        let l_uint: Vec<u64> = l_value.into_repr().as_ref().into();
        assert_eq!(l_uint[1], 0);
        assert_eq!(l_uint[2], 0);
        assert_eq!(l_uint[3], 0);
        let l_uint = l_uint[0];
        let m_value = self.get_assignment(m);
        let m_uint: Vec<u64> = m_value.into_repr().as_ref().into();
        assert_eq!(m_uint[1], 0);
        assert_eq!(m_uint[2], 0);
        assert_eq!(m_uint[3], 0);
        let m_uint = m_uint[0];

        let mut bit_location_b = vec![];
        let mut bit_location_a = vec![];
        for _ in 0..l_uint {
            bit_location_a.push(self.alloc(F::zero()))
        }

        for _ in 0..m_uint {
            bit_location_b.push(self.alloc(F::one()));
            bit_location_a.push(self.alloc(F::one()));
        }

        for _ in m_uint..b_max_lens as u64 {
            bit_location_b.push(self.alloc(F::zero()));
        }

        let tmplen = bit_location_a.len();
        for _ in tmplen..max_lens {
            bit_location_a.push(self.alloc(F::zero()));
        }
        // padding b
        // for _ in b_max_lens..max_lens {
        //     bit_location_b.push(Composer::<F>::null());
        // }

        Ok((bit_location_a, bit_location_b))
    }

    /// 1 Variable represent 32 bit. for sha256
    pub fn collect_bit_location_for_sha256(
        &mut self,
        max_lens: usize,
        bit_location: &Vec<Variable>,
    ) -> Result<Vec<Variable>, Error> {
        assert_eq!(max_lens % 32, 0);
        assert_eq!(max_lens, bit_location.len());
        assert!(self.program_width >= 5);
        
        // output bit_location for sha256 inputs
        let bit_location_value = self.get_assignments(&bit_location);
        let mut output_words = vec![];
        for i in 0..max_lens / 32 {
            let mut tmp_vars = vec![];
            for j in 0..8 {
                let tmp = bit_location_value[32 * i + 4 * j] * F::from(8u64)
                    + bit_location_value[32 * i + 4 * j + 1] * F::from(4u64)
                    + bit_location_value[32 * i + 4 * j + 2] * F::from(2u64)
                    + bit_location_value[32 * i + 4 * j + 3];
                tmp_vars.push(self.alloc(tmp));
                self.poly_gate(
                    vec![
                        (tmp_vars[j], -F::one()),
                        (bit_location[32 * i + 4 * j], F::from(8u64)),
                        (bit_location[32 * i + 4 * j + 1], F::from(4u64)),
                        (bit_location[32 * i + 4 * j + 2], F::from(2u64)),
                        (bit_location[32 * i + 4 * j + 3], F::one()),
                    ],
                    F::zero(),
                    F::zero(),
                );
            }

            let tmp_vars_value = self.get_assignments(&tmp_vars);
            let mut tmp2_vars = vec![];
            for j in 0..2 {
                let tmp = tmp_vars_value[4 * j] * F::from(1u64 << 12)
                    + tmp_vars_value[4 * j + 1] * F::from(1u64 << 8)
                    + tmp_vars_value[4 * j + 2] * F::from(1u64 << 4)
                    + tmp_vars_value[4 * j + 3];
                tmp2_vars.push(self.alloc(tmp));
                self.poly_gate(
                    vec![
                        (tmp2_vars[j], -F::one()),
                        (tmp_vars[4 * j], F::from(1u64 << 12)),
                        (tmp_vars[4 * j + 1], F::from(1u64 << 8)),
                        (tmp_vars[4 * j + 2], F::from(1u64 << 4)),
                        (tmp_vars[4 * j + 3], F::one()),
                    ],
                    F::zero(),
                    F::zero(),
                );
            }

            // 2 16bits
            let tmp2_vars_value = self.get_assignments(&tmp2_vars);

            let tmp = tmp2_vars_value[0] * F::from(1u64 << 16) + tmp2_vars_value[1];
            output_words.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (output_words[i], -F::one()),
                    (tmp2_vars[0], F::from(1u128 << 16)),
                    (tmp2_vars[1], F::one()),
                ],
                F::zero(),
                F::zero(),
            );
        }

        Ok(output_words)
    }

    /// ensure some positions are matched between "a" and "b". "b" is a public string.
    /// if any var is 0 in "b", we default that this byte is private (not match), otherwise must match to "a"
    pub fn add_public_match_no_custom_gate(
        &mut self,
        a: &Vec<Variable>,
        b: &Vec<Variable>,
        max_lens: usize,
    ) {
        assert_eq!(a.len(), max_lens);
        assert_eq!(b.len(), max_lens);

        // prove public_match
        // b * (a - b) === 0
        for i in 0..max_lens {
            let ci = self.sub(a[i], b[i]);
            self.mul_gate(ci, b[i], Composer::<F>::null());
        }

        // recommend hash "b" to compress public_input
    }

    /// Deprecated.
    /// ensure some positions are matched between "a" and "b". "b" is a public string.
    /// if any var is 0 in "b", we default that this byte is private (not match), otherwise must match to "a"
    pub fn add_public_match(
        &mut self,
        a: &Vec<Variable>,
        b: &Vec<Variable>,
        max_lens: usize,
    ) -> Result<(), Error> {
        // let max_lens = 2048;
        assert_eq!(a.len(), max_lens);
        assert_eq!(b.len(), max_lens);

        if !self.switches.enable_pubmatch {
            self.switches.enable_pubmatch = true;
        }
        if !self.selectors.contains_key("q_pubmatch") {
            let current_index = self.size();
            self.selectors
                .insert("q_pubmatch".to_string(), vec![F::zero(); current_index]);
        }

        // prove public_match
        // w0:a. w1:b.
        let mut current_index = self.size();
        for i in 0..max_lens {
            let wires = vec![a[i], b[i]];

            let index = self.insert_gate(wires);
            assert_eq!(current_index, index);

            self.selectors.get_mut("q_pubmatch").unwrap()[index] = F::one();

            current_index += 1;
        }

        // recommend hash "b" to compress public_input

        Ok(())
    }
}
