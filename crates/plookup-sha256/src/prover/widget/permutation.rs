use ark_ec::PairingEngine;
use ark_poly_commit::LinearCombination;
use ark_std::{cfg_into_iter, format, vec, vec::Vec};
use rand_core::RngCore;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::prover::{Error, Prover};
use crate::{coset_generator, Domain, Field};

use super::Widget;

pub(crate) struct PermutationWidget {
    program_width: usize,
    wire_labels: Vec<String>,
    sigma_labels: Vec<String>,
}

impl<'a> PermutationWidget {
    pub fn new(program_width: usize) -> Self {
        Self {
            program_width,
            wire_labels: (0..program_width).map(|i| format!("w_{}", i)).collect(),
            sigma_labels: (0..program_width).map(|i| format!("sigma_{}", i)).collect(),
        }
    }
}

impl<F: Field, D: Domain<F>, E: PairingEngine, R: RngCore> Widget<F, D, E, R>
    for PermutationWidget
{
    fn compute_oracles(
        &self,
        round: usize,
        prover: &mut Prover<F, D, E>,
        rng: &mut R,
    ) -> Result<(), Error> {
        if round == 2 {
            let values = prover.domain_values();
            let z = {
                let beta = prover.get_challenge("beta")?;
                let gamma = prover.get_challenge("gamma")?;
                let roots: Vec<_> = prover.domain.elements().collect();

                let n = prover.domain_size();
                let perms: Vec<_> = cfg_into_iter!((0..n))
                    .map(|i| {
                        let numerator_factor = |(j, w)| {
                            values[w][i] + coset_generator::<F>(j) * beta * roots[i] + gamma
                        };
                        let numerator = self
                            .wire_labels
                            .iter()
                            .enumerate()
                            .map(numerator_factor)
                            .product::<F>();

                        let denominator_factor =
                            |(w, sigma)| values[w][i] + beta * values[sigma][i] + gamma;
                        let denominator = self
                            .wire_labels
                            .iter()
                            .zip(self.sigma_labels.iter())
                            .map(denominator_factor)
                            .product::<F>();

                        numerator * denominator.inverse().unwrap()
                    })
                    .collect();

                let mut z = Vec::<F>::with_capacity(n);
                let mut acc = F::one();
                z.push(acc);
                (0..(n - 1)).for_each(|i| {
                    acc *= perms[i];
                    z.push(acc);
                });

                assert_eq!(z[n - 1] * perms[n - 1], F::one());

                z
            };

            prover.insert_with_blind("z", z, 2, rng);
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

        let beta = prover.get_challenge("beta")?;
        let gamma = prover.get_challenge("gamma")?;
        let alpha = prover.get_challenge("alpha")?;

        let values = prover.coset_values();
        let n = quotient.len();

        let ratio = prover.coset_size() / prover.domain_size();

        quotient.into_par_iter().enumerate().for_each(|(i, quot)| {
            let next_i = if i / ratio == (n / ratio - 1) {
                i % ratio
            } else {
                i + ratio
            };

            let numerator_factor = |(j, w)| {
                values[w][i] + coset_generator::<F>(j) * beta * values["linear"][i] + gamma
            };
            let numerator = values["z"][i]
                * self
                    .wire_labels
                    .par_iter()
                    .enumerate()
                    .map(numerator_factor)
                    .product::<F>();

            let denominator_factor = |(w, sigma)| values[w][i] + beta * values[sigma][i] + gamma;
            let denominator = values["z"][next_i]
                * self
                    .wire_labels
                    .par_iter()
                    .zip(self.sigma_labels.par_iter())
                    .map(denominator_factor)
                    .product::<F>();

            *quot += *combinator
                * (numerator - denominator
                    + (values["z"][i] - F::one()) * values["lagrange_1"][i] * alpha)
        });

        *combinator *= alpha.square();

        //free mem
        prover.remove_coset_values("z");
        prover.remove_coset_values("linear");
        prover.remove_coset_values("sigma_0");
        prover.remove_coset_values("sigma_1");
        prover.remove_coset_values("sigma_2");
        prover.remove_coset_values("sigma_3");

        Ok(())
    }

    fn compute_linear_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
    ) -> Result<(LinearCombination<F>, F), Error> {
        let beta = prover.get_challenge("beta")?;
        let gamma = prover.get_challenge("gamma")?;
        let alpha = prover.get_challenge("alpha")?;
        let zeta = prover.get_challenge("zeta")?;

        let mut w_zeta = self
            .wire_labels
            .iter()
            .map(|l| prover.evaluate(l, "zeta"))
            .collect::<Result<Vec<_>, Error>>()?;

        let mut sigma_labels: Vec<_> = self.sigma_labels.iter().collect();
        let last_sigma = sigma_labels.pop().unwrap();
        let sigma_zeta = sigma_labels
            .into_iter()
            .map(|l| prover.evaluate(l, "zeta"))
            .collect::<Result<Vec<_>, Error>>()?;

        let z_zeta_omega = prover.evaluate("z", "zeta_omega")?;

        let numerator_factor = |(j, &w)| w + coset_generator::<F>(j) * beta * zeta + gamma;
        let numerator = w_zeta
            .iter()
            .enumerate()
            .map(numerator_factor)
            .product::<F>();

        let denominator_factor = |(&w, &sigma)| w + beta * sigma + gamma;
        let denominator = beta
            * z_zeta_omega
            * w_zeta
                .iter()
                .zip(sigma_zeta.iter())
                .map(denominator_factor)
                .product::<F>();
        let lagrange_1_zeta = prover.domain.evaluate_lagrange_polynomial(1, &zeta);

        let lc = LinearCombination::new(
            "permutation",
            vec![
                (*combinator * (numerator + alpha * lagrange_1_zeta), "z"),
                (-*combinator * denominator, last_sigma),
            ],
        );

        let complement = {
            let last_w_zeta = w_zeta.pop().unwrap();
            let product = w_zeta
                .into_iter()
                .zip(sigma_zeta)
                .map(|(w, sigma)| w + beta * sigma + gamma)
                .product::<F>();
            *combinator * (product * (last_w_zeta + gamma) * z_zeta_omega + alpha * lagrange_1_zeta)
        };

        *combinator *= alpha.square();

        Ok((lc, complement))
    }
}
