use ark_ec::PairingEngine;
use ark_poly_commit::LinearCombination;
use ark_std::{cfg_into_iter, format, vec, vec::Vec};
use rand_core::RngCore;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::prover::Prover;
use crate::{Domain, Error, Field};

use super::Widget;

pub(crate) struct LookupWidget {
    program_width: usize,
    wire_labels: Vec<String>,
    table_column_labels: Vec<String>,
    sorted_list_labels: Vec<String>,
}

impl LookupWidget {
    pub fn new(program_width: usize) -> Self {
        Self {
            program_width,
            wire_labels: (0..program_width)
                .into_iter()
                .map(|i| format!("w_{}", i))
                .collect(),
            table_column_labels: (0..program_width + 1)
                .into_iter()
                .map(|i| format!("table_{}", i))
                .collect(),
            sorted_list_labels: (0..program_width + 1)
                .into_iter()
                .map(|i| format!("s_{}", i))
                .collect(),
        }
    }
}

impl<F: Field, D: Domain<F>, E: PairingEngine, R: RngCore> Widget<F, D, E, R> for LookupWidget {
    fn compute_oracles(
        &self,
        round: usize,
        prover: &mut Prover<F, D, E>,
        rng: &mut R,
    ) -> Result<(), Error> {
        // cal "s"
        if round == 1 {
            let eta = prover.get_challenge("eta")?;

            // original vec
            let values = prover.domain_values();
            //collect s0 s1 s2 s3 s4... into s
            let s = cfg_into_iter!((0..prover.domain_size()))
                .map(|i| {
                    combine(
                        eta,
                        self.sorted_list_labels
                            .iter()
                            .map(|l| values[l][i])
                            .collect(),
                    )
                })
                .collect();

            prover.insert_with_blind("s", s, 2, rng);
        }

        // cal "table" and "z_lookup"
        if round == 3 {
            let eta = prover.get_challenge("eta")?;
            let beta = prover.get_challenge("beta_1")?;
            let gamma = prover.get_challenge("gamma_1")?;

            let values = prover.domain_values();
            let n = prover.domain_size();
            let t: Vec<_> = cfg_into_iter!((0..n))
                .map(|i| {
                    combine(
                        eta,
                        self.table_column_labels
                            .iter()
                            .map(|l| values[l][i])
                            .collect(),
                    )
                })
                .collect();

            let v: Vec<_> = cfg_into_iter!((0..n))
                .map(|i| {
                    if values["q_lookup"][i].is_zero() {
                        F::zero()
                    } else {
                        let v = combine(
                            eta,
                            self.wire_labels //because 'wires' is 1 column less than tables
                                .iter()
                                .chain(vec!["q_table".to_string()].iter()) // so need add q_table
                                .map(|l| values[l][i])
                                .collect(),
                        );
                        v * values["q_lookup"][i]
                    }
                })
                .collect();

            let beta_gamma_factor = (beta + F::one()) * gamma;
            let mut z = Vec::<F>::with_capacity(n);
            let mut acc = F::one();
            z.push(acc);
            (0..(n - 1)).for_each(|i| {
                let numerator = (v[i] + gamma) * (t[i] + beta * t[i + 1] + beta_gamma_factor);
                let denominator =
                    gamma * (values["s"][i] + beta * values["s"][i + 1] + beta_gamma_factor);
                acc *= numerator * denominator.inverse().unwrap();
                z.push(acc);
            });
            assert_eq!(z[n - 1], F::one());

            prover.insert("table", t);
            prover.insert_with_blind("z_lookup", z, 2, rng);
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

        let eta = prover.get_challenge("eta")?;
        let beta = prover.get_challenge("beta_1")?;
        let gamma = prover.get_challenge("gamma_1")?;
        let alpha = prover.get_challenge("alpha")?;
        let values = prover.coset_values();

        let n = quotient.len();
        let t: Vec<_> = cfg_into_iter!((0..n))
            .map(|i| {
                combine(
                    eta,
                    self.table_column_labels
                        .iter()
                        .map(|l| values[l][i])
                        .collect(),
                )
            })
            .collect();
        let v: Vec<_> = cfg_into_iter!((0..n))
            .map(|i| {
                combine(
                    eta,
                    self.wire_labels
                        .iter()
                        .chain(vec!["q_table".to_string()].iter())
                        .map(|l| values[l][i])
                        .collect(),
                )
            })
            .collect();

        let beta_gamma_factor = (beta + F::one()) * gamma;
        let alpha_2 = alpha.square();

        let ratio = prover.coset_size() / prover.domain_size();

        quotient.into_par_iter().enumerate().for_each(|(i, quot)| {
            let next_i = if i / ratio == (n / ratio - 1) {
                i % ratio
            } else {
                i + ratio
            };

            let numerator = values["z_lookup"][i]
                * (values["q_lookup"][i] * v[i] + gamma)
                * (t[i] + beta * t[next_i] + beta_gamma_factor);
            let denominator = values["z_lookup"][next_i]
                * gamma
                * (values["s"][i] + beta * values["s"][next_i] + beta_gamma_factor);

            *quot += *combinator
                * (numerator - denominator
                    + (values["z_lookup"][i] - F::one()) * values["lagrange_1"][i] * alpha
                    + (values["z_lookup"][i] - F::one()) * values["lagrange_n"][i] * alpha_2)
        });

        *combinator *= alpha_2 * alpha;

        //free mem
        prover.remove_coset_values("q_lookup");
        prover.remove_coset_values("z_lookup");
        prover.remove_coset_values("q_table");

        Ok(())
    }

    fn compute_linear_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
    ) -> Result<(LinearCombination<F>, F), Error> {
        let eta = prover.get_challenge("eta")?;
        let beta = prover.get_challenge("beta_1")?;
        let gamma = prover.get_challenge("gamma_1")?;
        let alpha = prover.get_challenge("alpha")?;
        let zeta = prover.get_challenge("zeta")?;

        let w_zeta = self
            .wire_labels
            .iter()
            .chain(vec!["q_table".to_string()].iter())
            .map(|l| prover.evaluate(l, "zeta"))
            .collect::<Result<Vec<_>, Error>>()?;
        let q_loolup_zeta = prover.evaluate("q_lookup", "zeta")?;

        let s_zeta_omega = prover.evaluate("s", "zeta_omega")?;
        let z_lookup_zeta_omega = prover.evaluate("z_lookup", "zeta_omega")?;

        let table_lc = {
            let mut etas = Vec::with_capacity(self.program_width);
            let mut acc = F::one();
            for _ in 0..self.program_width + 1 {
                etas.push(acc);
                acc *= eta;
            }
            LinearCombination::new(
                "table",
                self.table_column_labels
                    .iter()
                    .zip(etas)
                    .map(|(l, e)| (e, l.to_string()))
                    .collect(),
            )
        };
        let table_zeta = prover.evaluate_linear_combination(&table_lc, "zeta")?;
        let table_zeta_omega = prover.evaluate_linear_combination(&table_lc, "zeta_omega")?;

        let alpha_2 = alpha.square();
        let beta_gamma_factor = (beta + F::one()) * gamma;
        let lagrange_1_zeta = prover.domain.evaluate_lagrange_polynomial(1, &zeta);
        let lagrange_n_zeta = prover
            .domain
            .evaluate_lagrange_polynomial(prover.domain_size(), &zeta);

        let numerator = {
            let v_zeta = combine(eta, w_zeta);

            (q_loolup_zeta * v_zeta + gamma)
                * (table_zeta + beta * table_zeta_omega + beta_gamma_factor)
        };
        let denominator = z_lookup_zeta_omega * gamma;

        //only s and zlookup
        let lc = LinearCombination::new(
            "lookup",
            vec![
                (
                    *combinator * (numerator + alpha * lagrange_1_zeta + alpha_2 * lagrange_n_zeta),
                    "z_lookup",
                ),
                (-*combinator * denominator, "s"),
            ],
        );

        // constant term
        let complement = *combinator
            * (z_lookup_zeta_omega * gamma * (beta * s_zeta_omega + beta_gamma_factor)
                + alpha * lagrange_1_zeta
                + alpha_2 * lagrange_n_zeta);

        *combinator *= alpha_2 * alpha;

        Ok((lc, complement))
    }
}

fn combine<F: Field>(challenge: F, mut values: Vec<F>) -> F {
    let mut acc = F::zero();
    while let Some(v) = values.pop() {
        acc = acc * challenge + v
    }

    acc
}
