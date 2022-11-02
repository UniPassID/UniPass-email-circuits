use ark_ec::PairingEngine;
use ark_poly_commit::LinearCombination;
use ark_std::cfg_into_iter;
use ark_std::{format, vec::Vec};
use rand_core::RngCore;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::prover::Prover;
use crate::{Domain, Error, Field};

use super::Widget;

pub(crate) struct SubStringWidget {
    program_width: usize,
    wire_labels: Vec<String>,
}

impl SubStringWidget {
    pub fn new(program_width: usize) -> Self {
        assert!(program_width >= 4);
        Self {
            program_width,
            wire_labels: (0..program_width)
                .into_iter()
                .map(|i| format!("w_{}", i))
                .collect(),
        }
    }
}

impl<F: Field, D: Domain<F>, E: PairingEngine, R: RngCore> Widget<F, D, E, R> for SubStringWidget {
    fn compute_oracles(
        &self,
        round: usize,
        prover: &mut Prover<F, D, E>,
        rng: &mut R,
    ) -> Result<(), Error> {
        if round == 2 {
            let domain_values = prover.domain_values();
            let n = prover.domain_size();

            // cal z
            let acc_elems: Vec<_> = cfg_into_iter!((0..n))
                .map(|i| {
                    domain_values["q_substring"][i]
                        * (domain_values["w_0"][i] * domain_values["w_1"][i]
                            - domain_values["w_2"][i] * domain_values["w_3"][i])
                })
                .collect();
            let mut z = Vec::<F>::with_capacity(n);
            let mut acc = F::zero();
            z.push(acc);
            (0..(n - 1)).for_each(|i| {
                acc += acc_elems[i];
                z.push(acc);
            });
            assert_eq!(z[n - 1] + acc_elems[n - 1], F::zero());

            prover.insert_with_blind("z_substring", z, 2, rng);
        }

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
        let n = quotient.len();

        let ratio = prover.coset_size() / prover.domain_size();
        let alpha_2 = alpha.square();
        let alpha_3 = alpha * alpha_2;
        let alpha_4 = alpha_2.square();
        let alpha_5 = alpha * alpha_4;

        quotient.into_par_iter().enumerate().for_each(|(i, quot)| {
            let next_i = if i / ratio == (n / ratio - 1) {
                i % ratio
            } else {
                i + ratio
            };

            let ra = values["q_substring_r"][i]
                * (values["w_1"][next_i]
                    * (values["w_4"][i] * values["w_0"][i] + values["w_1"][next_i]
                        - values["w_1"][i])
                    - values["w_0"][next_i]);

            let rb = values["q_substring_r"][i]
                * (values["w_3"][next_i]
                    * (values["w_4"][i] * values["w_2"][i] + values["w_3"][next_i]
                        - values["w_3"][i])
                    - values["w_2"][next_i]);

            let recur = values["z_substring"][next_i]
                - values["z_substring"][i]
                - values["q_substring"][i]
                    * (values["w_0"][i] * values["w_1"][i] - values["w_2"][i] * values["w_3"][i]);

            let zl1 = values["z_substring"][i] * values["lagrange_1"][i];

            let enforce_boola = values["q_substring_r"][i]
                * values["w_1"][next_i]
                * (values["w_1"][next_i] - F::one());
            let enforce_boolb = values["q_substring_r"][i]
                * values["w_3"][next_i]
                * (values["w_3"][next_i] - F::one());

            *quot += *combinator
                * (recur
                    + ra * alpha
                    + rb * alpha_2
                    + zl1 * alpha_3
                    + enforce_boola * alpha_4
                    + enforce_boolb * alpha_5);
        });

        *combinator *= alpha_5 * alpha;

        //free mem
        prover.remove_coset_values("z_substring");
        prover.remove_coset_values("q_substring");
        prover.remove_coset_values("q_substring_r");

        Ok(())
    }

    fn compute_linear_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
    ) -> Result<(LinearCombination<F>, F), Error> {
        let alpha = prover.get_challenge("alpha")?;
        let zeta = prover.get_challenge("zeta")?;

        let w0_zeta_omega = prover.evaluate("w_0", "zeta_omega")?;
        let w1_zeta_omega = prover.evaluate("w_1", "zeta_omega")?;
        let w2_zeta_omega = prover.evaluate("w_2", "zeta_omega")?;
        let w3_zeta_omega = prover.evaluate("w_3", "zeta_omega")?;
        let w0_zeta = prover.evaluate("w_0", "zeta")?;
        let w1_zeta = prover.evaluate("w_1", "zeta")?;
        let w2_zeta = prover.evaluate("w_2", "zeta")?;
        let w3_zeta = prover.evaluate("w_3", "zeta")?;
        let w4_zeta = prover.evaluate("w_4", "zeta")?;

        let z_substring_zeta_omega = prover.evaluate("z_substring", "zeta_omega")?;

        let alpha_2 = alpha.square();
        let alpha_3 = alpha * alpha_2;
        let alpha_4 = alpha_2.square();
        let alpha_5 = alpha * alpha_4;

        let lagrange_1_zeta = prover.domain.evaluate_lagrange_polynomial(1, &zeta);

        //
        let lc = LinearCombination::new(
            "substring",
            vec![
                (
                    *combinator * (w2_zeta * w3_zeta - w0_zeta * w1_zeta),
                    "q_substring",
                ),
                (
                    *combinator
                        * (alpha
                            * (w1_zeta_omega * (w4_zeta * w0_zeta + w1_zeta_omega - w1_zeta)
                                - w0_zeta_omega)
                            + alpha_2
                                * (w3_zeta_omega * (w4_zeta * w2_zeta + w3_zeta_omega - w3_zeta)
                                    - w2_zeta_omega)
                            + alpha_4 * w1_zeta_omega * (w1_zeta_omega - F::one())
                            + alpha_5 * w3_zeta_omega * (w3_zeta_omega - F::one())),
                    "q_substring_r",
                ),
                (
                    *combinator * (alpha_3 * lagrange_1_zeta - F::one()),
                    "z_substring",
                ),
            ],
        );

        // constant term
        let complement = *combinator * (-z_substring_zeta_omega);

        *combinator *= alpha_5 * alpha;

        Ok((lc, complement))
    }
}
