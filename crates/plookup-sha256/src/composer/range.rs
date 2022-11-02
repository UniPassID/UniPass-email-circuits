use super::{Composer, Variable};
use crate::{Error, Field};
use ark_ff::BigInteger;
use ark_std::{format, vec::Vec};

impl<F: Field> Composer<F> {
    /// here we enforce range constraint by quads (2-bit unit), so `num_bits` must be even.
    /// The quads are orgnized in the big-endian order.
    pub fn enforce_range(&mut self, var: Variable, num_bits: usize) -> Result<usize, Error> {
        if !self.enable_range {
            self.enable_range = true;
        }
        if !self.selectors.contains_key("q_range") {
            let current_index = self.size();
            self.selectors
                .insert("q_range".to_string(), vec![F::zero(); current_index]);
        }
        assert!(!self.is_finalized);
        assert!(self.program_width >= 4);

        assert_eq!((num_bits >> 1) << 1, num_bits);

        let value = self.assignments[var.0].into_repr();
        if value.num_bits() as usize > num_bits {
            return Err(Error::VariableOutOfRange(format!(
                "Variable {} has value {}, which exceeds the expected bit length of {}",
                var.0, value, num_bits
            )));
        }

        let mut accumulators = {
            let num_quads = num_bits >> 1;
            let num_gates = num_quads / self.program_width;

            let mut accumulators = Vec::with_capacity(num_gates * self.program_width);
            if num_quads % self.program_width != 0 {
                for _ in 0..self.program_width - num_quads % self.program_width {
                    accumulators.push(Self::null());
                }
            }
            accumulators.push(Self::null());

            let mut acc = F::zero();
            for i in (1..num_quads).rev() {
                // acc = 4 * acc + quad
                let quad = F::from_repr(BigInteger::from_bits_le(&[
                    value.get_bit(2 * i),
                    value.get_bit(2 * i + 1),
                ]))
                .unwrap();

                acc += acc;
                acc += acc;
                acc += quad;
                accumulators.push(self.alloc(acc));
            }

            assert_eq!(
                {
                    let quad = F::from_repr(BigInteger::from_bits_le(&[
                        value.get_bit(0),
                        value.get_bit(1),
                    ]))
                    .unwrap();
                    acc += acc;
                    acc += acc;

                    acc + quad
                },
                F::from_repr(value).unwrap()
            );

            accumulators
        };

        while accumulators.len() >= self.program_width {
            let index = self.insert_gate(accumulators.drain(0..self.program_width).collect());
            self.selectors.get_mut("q_range").unwrap()[index] = F::one();
        }
        let index = self.insert_gate(vec![var]);

        Ok(index)
    }
}
