use ark_ec::PairingEngine;
use ark_poly_commit::LinearCombination;
use ark_std::{format, vec, vec::Vec};
use rand_core::RngCore;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::prover::Prover;
use crate::{Domain, Error, Field};

use super::Widget;

pub(crate) struct ArithmeticWidget {
    wire_labels: Vec<String>,
    scaling_labels: Vec<String>,
}

impl<'a> ArithmeticWidget {
    pub fn new(program_width: usize) -> Self {
        assert!(program_width >= 2);
        Self {
            wire_labels: (0..program_width)
                .into_iter()
                .map(|i| format!("w_{}", i))
                .collect(),
            scaling_labels: (0..program_width)
                .into_iter()
                .map(|i| format!("q_{}", i))
                .collect(),
        }
    }
}

impl<F: Field, D: Domain<F>, E: PairingEngine, R: RngCore> Widget<F, D, E, R> for ArithmeticWidget {
    fn compute_oracles(&self, _: usize, _: &mut Prover<F, D, E>, _: &mut R) -> Result<(), Error> {
        Ok(())
    }

    fn compute_quotient_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
        quotient: &mut [F],
    ) -> Result<(), Error> {
        let len = quotient.len();
        assert_eq!(len, prover.coset_size());

        let values = prover.coset_values();

        let ratio = prover.coset_size() / prover.domain_size();
        let q0next_enabled = prover.enable_q0next;

        quotient.into_par_iter().enumerate().for_each(|(i, quot)| {
            let next_i = if i / ratio == (len / ratio - 1) {
                i % ratio
            } else {
                i + ratio
            };

            let sum = self
                .wire_labels
                .par_iter()
                .zip(self.scaling_labels.par_iter())
                .map(|(w, q)| values[w][i] * values[q][i])
                .sum::<F>();

            let mut arith_part = -values["pi"][i]
                    + values["q_m"][i] * values["w_0"][i] * values["w_1"][i]
                    + values["q_c"][i]
                    + sum;
            if q0next_enabled {
                arith_part += values["q0next"][i] * values["w_0"][next_i];
            }

            *quot += *combinator * arith_part;
        });

        let alpha = prover.get_challenge("alpha")?;
        *combinator *= alpha;

        //free mem
        prover.remove_coset_values("pi");

        Ok(())
    }

    fn compute_linear_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
    ) -> Result<(LinearCombination<F>, F), Error> {
        let w_0_zeta = prover.evaluate("w_0", "zeta")?;
        let w_1_zeta = prover.evaluate("w_1", "zeta")?;

        let mut terms = vec![
            (w_0_zeta * w_1_zeta, "q_m"),
            (F::one(), "q_c"),
        ];
        if prover.enable_q0next {
            let w0_zeta_omega = prover.evaluate("w_0", "zeta_omega")?;
            terms.push((w0_zeta_omega, "q0next"));
        }
        for (w, q) in self.wire_labels.iter().zip(self.scaling_labels.iter()) {
            let w_zeta = prover.evaluate(w, "zeta")?;
            terms.push((w_zeta, q));
        }

        let lc = LinearCombination::new("arithmetic", terms);

        let alpha = prover.get_challenge("alpha")?;
        *combinator *= alpha;

        Ok((lc, F::zero()))
    }
}
