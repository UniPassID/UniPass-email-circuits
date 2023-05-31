use ark_ec::PairingEngine;
use ark_poly_commit::LinearCombination;
use ark_std::{format, vec::Vec};
use rand_core::RngCore;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::prover::Prover;
use crate::{Domain, Error, Field};

use super::Widget;

pub(crate) struct RangeWidget {
    program_width: usize,
    wire_labels: Vec<String>,
}

impl RangeWidget {
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

impl<F: Field, D: Domain<F>, E: PairingEngine, R: RngCore> Widget<F, D, E, R> for RangeWidget {
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

            let mut quads: Vec<_> = (0..self.program_width - 1)
                .into_par_iter()
                .map(|j| {
                    quad(
                        values[&self.wire_labels[j]][i],
                        values[&self.wire_labels[j + 1]][i],
                    )
                })
                .collect();
            quads.push(quad(
                values[&self.wire_labels[self.program_width - 1]][i],
                values[&self.wire_labels[0]][next_i],
            ));

            *quot += *combinator * values["q_range"][i] * combine(eta, quads);
        });

        *combinator *= alpha;

        //free mem
        prover.remove_coset_values("q_range");

        Ok(())
    }

    fn compute_linear_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
    ) -> Result<(LinearCombination<F>, F), Error> {
        let eta = prover.get_challenge("eta")?;
        let alpha = prover.get_challenge("alpha")?;

        let quads = {
            let w_zeta = self
                .wire_labels
                .iter()
                .map(|l| prover.evaluate(l, "zeta"))
                .collect::<Result<Vec<_>, Error>>()?;
            let w_zeta_omega = prover.evaluate("w_0", "zeta_omega")?;

            let mut quads: Vec<_> = (0..self.program_width - 1)
                .map(|j| quad(w_zeta[j], w_zeta[j + 1]))
                .collect();
            quads.push(quad(w_zeta[self.program_width - 1], w_zeta_omega));

            quads
        };

        // eta3*D(w00-4w3) + eta2*D(w3-4w2) + eta*D(w2-4w1) + D(w1-4w0)
        let lc = LinearCombination::new(
            "range",
            vec![(*combinator * combine(eta, quads), "q_range")],
        );

        *combinator *= alpha;

        Ok((lc, F::zero()))
    }
}

#[inline]
fn quad<F: Field>(lower: F, higher: F) -> F {
    let mut v = lower;
    v += v;
    v += v;
    v = higher - v;
    (0..4).map(|i| v - F::from(i as u64)).product()
}

fn combine<F: Field>(challenge: F, mut values: Vec<F>) -> F {
    let mut acc = F::zero();
    while let Some(v) = values.pop() {
        acc = acc * challenge + v
    }

    acc
}
