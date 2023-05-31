use ark_ec::PairingEngine;
use ark_poly_commit::LinearCombination;
use ark_std::{format, vec::Vec};
use rand_core::RngCore;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::prover::Prover;
use crate::{Domain, Error, Field};

use super::Widget;

pub(crate) struct MiMCWidget {
    program_width: usize,
    wire_labels: Vec<String>,
}

impl MiMCWidget {
    pub fn new(program_width: usize) -> Self {
        assert!(program_width >= 4);
        Self {
            program_width,
            wire_labels: (0..program_width)
                .map(|i| format!("w_{}", i))
                .collect(),
        }
    }
}

impl<F: Field, D: Domain<F>, E: PairingEngine, R: RngCore> Widget<F, D, E, R> for MiMCWidget {
    fn compute_oracles(&self, _: usize, _: &mut Prover<F, D, E>, _: &mut R) -> Result<(), Error> {
        Ok(())
    }

    /// q_mimc((w3 - (w0+w2)^2) + eta*(w0next - w3^2 * (w0+w2) - w1))
    fn compute_quotient_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
        quotient: &mut [F],
    ) -> Result<(), Error> {
        assert_eq!(quotient.len(), prover.coset_size());

        let alpha = prover.get_challenge("alpha")?;
        let eta = prover.get_challenge("eta")?;

        let values = prover.coset_values();
        let n = quotient.len();

        let ratio = prover.coset_size() / prover.domain_size();

        quotient.into_par_iter().enumerate().for_each(|(i, quot)| {
            let next_i = if i / ratio == (n / ratio - 1) {
                i % ratio
            } else {
                i + ratio
            };

            let tmp1 = values["w_0"][i] + values["w_2"][i];
            let part1 = values["w_3"][i] - tmp1.square();

            *quot += *combinator
                * values["q_mimc"][i]
                * (values["w_0"][next_i] - values["w_3"][i].square() * tmp1 - values["w_1"][i]
                    + eta * part1);
        });

        *combinator *= alpha;

        //free mem
        prover.remove_coset_values("q_mimc");

        Ok(())
    }

    fn compute_linear_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
    ) -> Result<(LinearCombination<F>, F), Error> {
        let eta = prover.get_challenge("eta")?;
        let alpha = prover.get_challenge("alpha")?;

        let w_zeta = self
            .wire_labels
            .iter()
            .map(|l| prover.evaluate(l, "zeta"))
            .collect::<Result<Vec<_>, Error>>()?;
        let w0_zeta_omega = prover.evaluate("w_0", "zeta_omega")?;

        let tmp1 = w_zeta[0] + w_zeta[2];
        let part1 = w_zeta[3] - tmp1.square();

        let res = w0_zeta_omega - w_zeta[3].square() * tmp1 - w_zeta[1] + eta * part1;

        //
        let lc = LinearCombination::new("mimc", vec![(*combinator * res, "q_mimc")]);

        *combinator *= alpha;

        Ok((lc, F::zero()))
    }
}
