use super::{Composer, Variable};
use crate::{Error, Field};
use ark_std::{format, vec::Vec};

impl<F: Field> Composer<F> {
    /// "b" is substring of "a". should be padding to the max len.
    /// a_max_lens == 2048, b_max_lens == 192.
    /// l is the start index of "b" in "a".
    /// m is the actual length of "b"
    pub fn add_substring_mask_poly(
        &mut self,
        a: &Vec<Variable>,
        b: &Vec<Variable>,
        mask: Variable,
        l: Variable,
        m: Variable,
    ) -> Result<(Vec<Variable>, Variable), Error> {
        let max_lens = 2048;
        let b_max_lens = 192;
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
        assert_eq!(b.len(), b_max_lens);
        let mut b = b.clone();

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

        let mut comb = F::one();
        let mut mask_poly_b = vec![];
        let mut bit_location_b = vec![];

        let mut mask_poly_a = vec![];
        let mut bit_location_a = vec![];
        for _ in 0..l_uint {
            mask_poly_a.push(self.alloc(F::zero()));
            bit_location_a.push(self.alloc(F::zero()))
        }

        for _ in 0..m_uint {
            mask_poly_b.push(self.alloc(comb));
            mask_poly_a.push(self.alloc(comb));
            comb *= r_value;
            bit_location_b.push(self.alloc(F::one()));
            bit_location_a.push(self.alloc(F::one()));
        }

        for _ in m_uint..b_max_lens as u64 {
            mask_poly_b.push(self.alloc(F::zero()));
            bit_location_b.push(self.alloc(F::zero()));
        }

        let tmplen = mask_poly_a.len();
        for _ in tmplen..max_lens {
            mask_poly_a.push(self.alloc(F::zero()));
            bit_location_a.push(self.alloc(F::zero()));
        }
        // padding b
        for _ in b_max_lens..max_lens {
            mask_poly_b.push(Composer::<F>::null());
            bit_location_b.push(Composer::<F>::null());
            b.push(Composer::<F>::null());
        }

        // prove ra rb. put 'mask poly' into witnesses.
        // w0:mask_poly_a. w1:bit_location_a. w2:mask_poly_b. w3:bit_location_b. w4: mask_r

        // must have this line at first
        let index = self.insert_gate(vec![
            Composer::<F>::null(),
            Composer::<F>::null(),
            Composer::<F>::null(),
            Composer::<F>::null(),
            mask,
        ]);
        self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::one();

        let mut current_index = self.size();
        for i in 0..max_lens {
            let wires = vec![
                mask_poly_a[i],
                bit_location_a[i],
                mask_poly_b[i],
                bit_location_b[i],
                mask,
            ];

            let index = self.insert_gate(wires);
            assert_eq!(current_index, index);

            self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::one();
            if i == max_lens - 1 {
                self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::zero();
            }

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

        // bool constraints are in the custom gate

        // output bit_location_a
        let bit_location_a_value = self.get_assignments(&bit_location_a);
        let mut output_bits_a = vec![];
        for i in 0..bit_location_a.len() / 252 {
            let mut tmp_vars = vec![];
            for j in 0..63 {
                let tmp = bit_location_a_value[252 * i + 4 * j] * F::from(8u64)
                    + bit_location_a_value[252 * i + 4 * j + 1] * F::from(4u64)
                    + bit_location_a_value[252 * i + 4 * j + 2] * F::from(2u64)
                    + bit_location_a_value[252 * i + 4 * j + 3];
                tmp_vars.push(self.alloc(tmp));
                self.poly_gate(
                    vec![
                        (tmp_vars[j], -F::one()),
                        (bit_location_a[252 * i + 4 * j], F::from(8u64)),
                        (bit_location_a[252 * i + 4 * j + 1], F::from(4u64)),
                        (bit_location_a[252 * i + 4 * j + 2], F::from(2u64)),
                        (bit_location_a[252 * i + 4 * j + 3], F::one()),
                    ],
                    F::zero(),
                    F::zero(),
                );
            }

            let tmp_vars_value = self.get_assignments(&tmp_vars);
            let mut tmp2_vars = vec![];
            for j in 0..15 {
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
            let tmp = tmp_vars_value[60] * F::from(1u64 << 8)
                + tmp_vars_value[61] * F::from(1u64 << 4)
                + tmp_vars_value[62];
            tmp2_vars.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (tmp2_vars[15], -F::one()),
                    (tmp_vars[60], F::from(1u64 << 8)),
                    (tmp_vars[61], F::from(1u64 << 4)),
                    (tmp_vars[62], F::one()),
                ],
                F::zero(),
                F::zero(),
            );

            let tmp2_vars_value = self.get_assignments(&tmp2_vars);
            let mut tmp3_vars = vec![];
            for j in 0..3 {
                let tmp = tmp2_vars_value[4 * j] * F::from(1u64 << 48)
                    + tmp2_vars_value[4 * j + 1] * F::from(1u64 << 32)
                    + tmp2_vars_value[4 * j + 2] * F::from(1u64 << 16)
                    + tmp2_vars_value[4 * j + 3];
                tmp3_vars.push(self.alloc(tmp));
                self.poly_gate(
                    vec![
                        (tmp3_vars[j], -F::one()),
                        (tmp2_vars[4 * j], F::from(1u64 << 48)),
                        (tmp2_vars[4 * j + 1], F::from(1u64 << 32)),
                        (tmp2_vars[4 * j + 2], F::from(1u64 << 16)),
                        (tmp2_vars[4 * j + 3], F::one()),
                    ],
                    F::zero(),
                    F::zero(),
                );
            }
            let tmp = tmp2_vars_value[12] * F::from(1u64 << 44)
                + tmp2_vars_value[13] * F::from(1u64 << 28)
                + tmp2_vars_value[14] * F::from(1u64 << 12)
                + tmp2_vars_value[15];
            tmp3_vars.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (tmp3_vars[3], -F::one()),
                    (tmp2_vars[12], F::from(1u64 << 44)),
                    (tmp2_vars[13], F::from(1u64 << 28)),
                    (tmp2_vars[14], F::from(1u64 << 12)),
                    (tmp2_vars[15], F::one()),
                ],
                F::zero(),
                F::zero(),
            );

            let tmp3_vars_value = self.get_assignments(&tmp3_vars);
            let tmp = tmp3_vars_value[0] * F::from(1u128 << 100) * F::from(1u128 << 88)
                + tmp3_vars_value[1] * F::from(1u128 << 124)
                + tmp3_vars_value[2] * F::from(1u64 << 60)
                + tmp3_vars_value[3];
            output_bits_a.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (output_bits_a[i], -F::one()),
                    (tmp3_vars[0], F::from(1u128 << 100) * F::from(1u128 << 88)),
                    (tmp3_vars[1], F::from(1u128 << 124)),
                    (tmp3_vars[2], F::from(1u64 << 60)),
                    (tmp3_vars[3], F::one()),
                ],
                F::zero(),
                F::zero(),
            );
        }
        // 32bits left
        let mut tmp_vars = vec![];
        for i in 0..8 {
            let tmp = bit_location_a_value[2016 + 4 * i] * F::from(8u64)
                + bit_location_a_value[2016 + 4 * i + 1] * F::from(4u64)
                + bit_location_a_value[2016 + 4 * i + 2] * F::from(2u64)
                + bit_location_a_value[2016 + 4 * i + 3];
            tmp_vars.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (tmp_vars[i], -F::one()),
                    (bit_location_a[2016 + 4 * i], F::from(8u64)),
                    (bit_location_a[2016 + 4 * i + 1], F::from(4u64)),
                    (bit_location_a[2016 + 4 * i + 2], F::from(2u64)),
                    (bit_location_a[2016 + 4 * i + 3], F::one()),
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

        let tmp2_vars_value = self.get_assignments(&tmp2_vars);
        let tmp = tmp2_vars_value[0] * F::from(1u64 << 16) + tmp2_vars_value[1];
        output_bits_a.push(self.alloc(tmp));
        self.poly_gate(
            vec![
                (output_bits_a[8], -F::one()),
                (tmp2_vars[0], F::from(1u64 << 16)),
                (tmp2_vars[1], F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        // output bit_location_b
        let bit_location_b_value = self.get_assignments(&bit_location_b);
        let mut tmp_vars = vec![];
        for i in 0..48 {
            let tmp = bit_location_b_value[4 * i] * F::from(8u64)
                + bit_location_b_value[4 * i + 1] * F::from(4u64)
                + bit_location_b_value[4 * i + 2] * F::from(2u64)
                + bit_location_b_value[4 * i + 3];
            tmp_vars.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (tmp_vars[i], -F::one()),
                    (bit_location_b[4 * i], F::from(8u64)),
                    (bit_location_b[4 * i + 1], F::from(4u64)),
                    (bit_location_b[4 * i + 2], F::from(2u64)),
                    (bit_location_b[4 * i + 3], F::one()),
                ],
                F::zero(),
                F::zero(),
            );
        }
        let tmp_vars_value = self.get_assignments(&tmp_vars);
        let mut tmp2_vars = vec![];
        for j in 0..12 {
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
        let tmp2_vars_value = self.get_assignments(&tmp2_vars);
        let mut tmp3_vars = vec![];
        for j in 0..3 {
            let tmp = tmp2_vars_value[4 * j] * F::from(1u64 << 48)
                + tmp2_vars_value[4 * j + 1] * F::from(1u64 << 32)
                + tmp2_vars_value[4 * j + 2] * F::from(1u64 << 16)
                + tmp2_vars_value[4 * j + 3];
            tmp3_vars.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (tmp3_vars[j], -F::one()),
                    (tmp2_vars[4 * j], F::from(1u64 << 48)),
                    (tmp2_vars[4 * j + 1], F::from(1u64 << 32)),
                    (tmp2_vars[4 * j + 2], F::from(1u64 << 16)),
                    (tmp2_vars[4 * j + 3], F::one()),
                ],
                F::zero(),
                F::zero(),
            );
        }
        let tmp3_vars_value = self.get_assignments(&tmp3_vars);
        let tmp = tmp3_vars_value[0] * F::from(1u128 << 64) * F::from(1u128 << 64)
            + tmp3_vars_value[1] * F::from(1u128 << 64)
            + tmp3_vars_value[2];
        let output_bits_b = self.alloc(tmp);
        self.poly_gate(
            vec![
                (output_bits_b, -F::one()),
                (tmp3_vars[0], F::from(1u128 << 64) * F::from(1u128 << 64)),
                (tmp3_vars[1], F::from(1u128 << 64)),
                (tmp3_vars[2], F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        Ok((output_bits_a, output_bits_b))
    }

    /// a.len() == 1024
    pub fn add_substring_mask_poly_1024(
        &mut self,
        a: &Vec<Variable>,
        b: &Vec<Variable>,
        mask: Variable,
        l: Variable,
        m: Variable,
    ) -> Result<(Vec<Variable>, Variable), Error> {
        let max_lens = 1024;
        let b_max_lens = 192;
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
        assert_eq!(b.len(), b_max_lens);
        let mut b = b.clone();

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

        let mut comb = F::one();
        let mut mask_poly_b = vec![];
        let mut bit_location_b = vec![];

        let mut mask_poly_a = vec![];
        let mut bit_location_a = vec![];
        for _ in 0..l_uint {
            mask_poly_a.push(self.alloc(F::zero()));
            bit_location_a.push(self.alloc(F::zero()))
        }

        for _ in 0..m_uint {
            mask_poly_b.push(self.alloc(comb));
            mask_poly_a.push(self.alloc(comb));
            comb *= r_value;
            bit_location_b.push(self.alloc(F::one()));
            bit_location_a.push(self.alloc(F::one()));
        }

        for _ in m_uint..b_max_lens as u64 {
            mask_poly_b.push(self.alloc(F::zero()));
            bit_location_b.push(self.alloc(F::zero()));
        }

        let tmplen = mask_poly_a.len();
        for _ in tmplen..max_lens {
            mask_poly_a.push(self.alloc(F::zero()));
            bit_location_a.push(self.alloc(F::zero()));
        }
        // padding b
        for _ in b_max_lens..max_lens {
            mask_poly_b.push(Composer::<F>::null());
            bit_location_b.push(Composer::<F>::null());
            b.push(Composer::<F>::null());
        }

        // prove ra rb.
        // w0:mask_poly_a. w1:bit_location_a. w2:mask_poly_b. w3:bit_location_b. w4: mask_r

        // must have this line at first
        let index = self.insert_gate(vec![
            Composer::<F>::null(),
            Composer::<F>::null(),
            Composer::<F>::null(),
            Composer::<F>::null(),
            mask,
        ]);
        self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::one();

        let mut current_index = self.size();
        for i in 0..max_lens {
            let wires = vec![
                mask_poly_a[i],
                bit_location_a[i],
                mask_poly_b[i],
                bit_location_b[i],
                mask,
            ];

            let index = self.insert_gate(wires);
            assert_eq!(current_index, index);

            self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::one();
            if i == max_lens - 1 {
                self.selectors.get_mut(&format!("q_substring_r")).unwrap()[index] = F::zero();
            }

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

        // output bit_location_a
        let bit_location_a_value = self.get_assignments(&bit_location_a);
        let mut output_bits_a = vec![];
        for i in 0..bit_location_a.len() / 252 {
            let mut tmp_vars = vec![];
            for j in 0..63 {
                let tmp = bit_location_a_value[252 * i + 4 * j] * F::from(8u64)
                    + bit_location_a_value[252 * i + 4 * j + 1] * F::from(4u64)
                    + bit_location_a_value[252 * i + 4 * j + 2] * F::from(2u64)
                    + bit_location_a_value[252 * i + 4 * j + 3];
                tmp_vars.push(self.alloc(tmp));
                self.poly_gate(
                    vec![
                        (tmp_vars[j], -F::one()),
                        (bit_location_a[252 * i + 4 * j], F::from(8u64)),
                        (bit_location_a[252 * i + 4 * j + 1], F::from(4u64)),
                        (bit_location_a[252 * i + 4 * j + 2], F::from(2u64)),
                        (bit_location_a[252 * i + 4 * j + 3], F::one()),
                    ],
                    F::zero(),
                    F::zero(),
                );
            }

            let tmp_vars_value = self.get_assignments(&tmp_vars);
            let mut tmp2_vars = vec![];
            for j in 0..15 {
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
            let tmp = tmp_vars_value[60] * F::from(1u64 << 8)
                + tmp_vars_value[61] * F::from(1u64 << 4)
                + tmp_vars_value[62];
            tmp2_vars.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (tmp2_vars[15], -F::one()),
                    (tmp_vars[60], F::from(1u64 << 8)),
                    (tmp_vars[61], F::from(1u64 << 4)),
                    (tmp_vars[62], F::one()),
                ],
                F::zero(),
                F::zero(),
            );

            let tmp2_vars_value = self.get_assignments(&tmp2_vars);
            let mut tmp3_vars = vec![];
            for j in 0..3 {
                let tmp = tmp2_vars_value[4 * j] * F::from(1u64 << 48)
                    + tmp2_vars_value[4 * j + 1] * F::from(1u64 << 32)
                    + tmp2_vars_value[4 * j + 2] * F::from(1u64 << 16)
                    + tmp2_vars_value[4 * j + 3];
                tmp3_vars.push(self.alloc(tmp));
                self.poly_gate(
                    vec![
                        (tmp3_vars[j], -F::one()),
                        (tmp2_vars[4 * j], F::from(1u64 << 48)),
                        (tmp2_vars[4 * j + 1], F::from(1u64 << 32)),
                        (tmp2_vars[4 * j + 2], F::from(1u64 << 16)),
                        (tmp2_vars[4 * j + 3], F::one()),
                    ],
                    F::zero(),
                    F::zero(),
                );
            }
            let tmp = tmp2_vars_value[12] * F::from(1u64 << 44)
                + tmp2_vars_value[13] * F::from(1u64 << 28)
                + tmp2_vars_value[14] * F::from(1u64 << 12)
                + tmp2_vars_value[15];
            tmp3_vars.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (tmp3_vars[3], -F::one()),
                    (tmp2_vars[12], F::from(1u64 << 44)),
                    (tmp2_vars[13], F::from(1u64 << 28)),
                    (tmp2_vars[14], F::from(1u64 << 12)),
                    (tmp2_vars[15], F::one()),
                ],
                F::zero(),
                F::zero(),
            );

            let tmp3_vars_value = self.get_assignments(&tmp3_vars);
            let tmp = tmp3_vars_value[0] * F::from(1u128 << 100) * F::from(1u128 << 88)
                + tmp3_vars_value[1] * F::from(1u128 << 124)
                + tmp3_vars_value[2] * F::from(1u64 << 60)
                + tmp3_vars_value[3];
            output_bits_a.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (output_bits_a[i], -F::one()),
                    (tmp3_vars[0], F::from(1u128 << 100) * F::from(1u128 << 88)),
                    (tmp3_vars[1], F::from(1u128 << 124)),
                    (tmp3_vars[2], F::from(1u64 << 60)),
                    (tmp3_vars[3], F::one()),
                ],
                F::zero(),
                F::zero(),
            );
        }
        // 16 left
        let mut tmp_vars = vec![];
        for i in 0..4 {
            let tmp = bit_location_a_value[1008 + 4 * i] * F::from(8u64)
                + bit_location_a_value[1008 + 4 * i + 1] * F::from(4u64)
                + bit_location_a_value[1008 + 4 * i + 2] * F::from(2u64)
                + bit_location_a_value[1008 + 4 * i + 3];
            tmp_vars.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (tmp_vars[i], -F::one()),
                    (bit_location_a[1008 + 4 * i], F::from(8u64)),
                    (bit_location_a[1008 + 4 * i + 1], F::from(4u64)),
                    (bit_location_a[1008 + 4 * i + 2], F::from(2u64)),
                    (bit_location_a[1008 + 4 * i + 3], F::one()),
                ],
                F::zero(),
                F::zero(),
            );
        }
        let tmp_vars_value = self.get_assignments(&tmp_vars);
        let tmp = tmp_vars_value[0] * F::from(1u64 << 12)
            + tmp_vars_value[1] * F::from(1u64 << 8)
            + tmp_vars_value[2] * F::from(1u64 << 4)
            + tmp_vars_value[3];
        output_bits_a.push(self.alloc(tmp));
        self.poly_gate(
            vec![
                (output_bits_a[4], -F::one()),
                (tmp_vars[0], F::from(1u64 << 12)),
                (tmp_vars[1], F::from(1u64 << 8)),
                (tmp_vars[2], F::from(1u64 << 4)),
                (tmp_vars[3], F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        // output bit_location_b
        let bit_location_b_value = self.get_assignments(&bit_location_b);
        let mut tmp_vars = vec![];
        for i in 0..48 {
            let tmp = bit_location_b_value[4 * i] * F::from(8u64)
                + bit_location_b_value[4 * i + 1] * F::from(4u64)
                + bit_location_b_value[4 * i + 2] * F::from(2u64)
                + bit_location_b_value[4 * i + 3];
            tmp_vars.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (tmp_vars[i], -F::one()),
                    (bit_location_b[4 * i], F::from(8u64)),
                    (bit_location_b[4 * i + 1], F::from(4u64)),
                    (bit_location_b[4 * i + 2], F::from(2u64)),
                    (bit_location_b[4 * i + 3], F::one()),
                ],
                F::zero(),
                F::zero(),
            );
        }
        let tmp_vars_value = self.get_assignments(&tmp_vars);
        let mut tmp2_vars = vec![];
        for j in 0..12 {
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
        let tmp2_vars_value = self.get_assignments(&tmp2_vars);
        let mut tmp3_vars = vec![];
        for j in 0..3 {
            let tmp = tmp2_vars_value[4 * j] * F::from(1u64 << 48)
                + tmp2_vars_value[4 * j + 1] * F::from(1u64 << 32)
                + tmp2_vars_value[4 * j + 2] * F::from(1u64 << 16)
                + tmp2_vars_value[4 * j + 3];
            tmp3_vars.push(self.alloc(tmp));
            self.poly_gate(
                vec![
                    (tmp3_vars[j], -F::one()),
                    (tmp2_vars[4 * j], F::from(1u64 << 48)),
                    (tmp2_vars[4 * j + 1], F::from(1u64 << 32)),
                    (tmp2_vars[4 * j + 2], F::from(1u64 << 16)),
                    (tmp2_vars[4 * j + 3], F::one()),
                ],
                F::zero(),
                F::zero(),
            );
        }
        let tmp3_vars_value = self.get_assignments(&tmp3_vars);
        let tmp = tmp3_vars_value[0] * F::from(1u128 << 64) * F::from(1u128 << 64)
            + tmp3_vars_value[1] * F::from(1u128 << 64)
            + tmp3_vars_value[2];
        let output_bits_b = self.alloc(tmp);
        self.poly_gate(
            vec![
                (output_bits_b, -F::one()),
                (tmp3_vars[0], F::from(1u128 << 64) * F::from(1u128 << 64)),
                (tmp3_vars[1], F::from(1u128 << 64)),
                (tmp3_vars[2], F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        Ok((output_bits_a, output_bits_b))
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
