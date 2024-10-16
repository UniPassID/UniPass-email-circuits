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

            *quot += *combinator
                * values["q_arith"][i]
                * (-values["pi"][i]
                    + values["q_m"][i] * values["w_0"][i] * values["w_1"][i]
                    + values["q_c"][i]
                    + values["q0next"][i] * values["w_0"][next_i]
                    + sum);
        });

        let alpha = prover.get_challenge("alpha")?;
        *combinator *= alpha;

        //free mem
        prover.remove_coset_values("q_arith");
        prover.remove_coset_values("pi");

        Ok(())
    }

    fn compute_linear_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
    ) -> Result<(LinearCombination<F>, F), Error> {
        let q_arith_zeta = *combinator * prover.evaluate("q_arith", "zeta")?;
        let w_0_zeta = prover.evaluate("w_0", "zeta")?;
        let w_1_zeta = prover.evaluate("w_1", "zeta")?;
        let w0_zeta_omega = prover.evaluate("w_0", "zeta_omega")?;

        let mut terms = vec![
            (q_arith_zeta * w_0_zeta * w_1_zeta, "q_m"),
            (q_arith_zeta, "q_c"),
            (q_arith_zeta * w0_zeta_omega, "q0next"),
        ];
        for (w, q) in self.wire_labels.iter().zip(self.scaling_labels.iter()) {
            let w_zeta = prover.evaluate(w, "zeta")?;
            terms.push((q_arith_zeta * w_zeta, q));
        }

        let lc = LinearCombination::new("arithmetic", terms);

        let alpha = prover.get_challenge("alpha")?;
        *combinator *= alpha;

        Ok((lc, F::zero()))
    }
}
