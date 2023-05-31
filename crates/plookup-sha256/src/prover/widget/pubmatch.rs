use ark_ec::PairingEngine;
use ark_poly_commit::LinearCombination;
use ark_std::{format, vec::Vec};
use rand_core::RngCore;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::prover::Prover;
use crate::{Domain, Error, Field};

use super::Widget;

pub(crate) struct PubMatchWidget {
    program_width: usize,
    wire_labels: Vec<String>,
}

impl PubMatchWidget {
    pub fn new(program_width: usize) -> Self {
        assert!(program_width >= 4);
        Self {
            program_width,
            wire_labels: (0..program_width).map(|i| format!("w_{}", i)).collect(),
        }
    }
}

impl<F: Field, D: Domain<F>, E: PairingEngine, R: RngCore> Widget<F, D, E, R> for PubMatchWidget {
    fn compute_oracles(&self, _: usize, _: &mut Prover<F, D, E>, _: &mut R) -> Result<(), Error> {
        Ok(())
    }

    fn compute_quotient_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
        quotient: &mut [F],
    ) -> Result<(), Error> {
        assert_eq!(quotient.len(), prover.coset_size());

        let alpha = prover.get_challenge("alpha")?;

        let values = prover.coset_values();

        quotient.into_par_iter().enumerate().for_each(|(i, quot)| {
            let pubmatch =
                values["q_pubmatch"][i] * values["w_1"][i] * (values["w_0"][i] - values["w_1"][i]);

            *quot += *combinator * (pubmatch);
        });

        *combinator *= alpha;

        //free mem
        prover.remove_coset_values("q_pubmatch");

        Ok(())
    }

    fn compute_linear_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
    ) -> Result<(LinearCombination<F>, F), Error> {
        let alpha = prover.get_challenge("alpha")?;

        let w0_zeta = prover.evaluate("w_0", "zeta")?;
        let w1_zeta = prover.evaluate("w_1", "zeta")?;

        let lc = LinearCombination::new(
            "pubmatch",
            vec![(*combinator * (w1_zeta * (w0_zeta - w1_zeta)), "q_pubmatch")],
        );

        *combinator *= alpha;

        Ok((lc, F::zero()))
    }
}
