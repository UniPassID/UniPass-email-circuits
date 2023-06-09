use ark_ec::PairingEngine;
use ark_poly_commit::LinearCombination;
use rand_core::RngCore;

use crate::prover::Prover;
use crate::{Domain, Error, Field};

mod arithmetic;
pub(crate) use arithmetic::ArithmeticWidget;

mod permutation;
pub(crate) use permutation::PermutationWidget;

mod range;
pub(crate) use range::RangeWidget;

mod lookup;
pub(crate) use lookup::LookupWidget;

mod substring;
pub(crate) use substring::SubStringWidget;

mod pubmatch;
pub(crate) use pubmatch::PubMatchWidget;

pub(crate) trait Widget<F: Field, D: Domain<F>, E: PairingEngine, R: RngCore> {
    /// Polynomials to be calculated in the Prove stage ("s","z","zlookup"...)
    fn compute_oracles(
        &self,
        round: usize,
        prover: &mut Prover<F, D, E>,
        rng: &mut R,
    ) -> Result<(), Error>;

    /// The part of "t" that belongs to the widget
    fn compute_quotient_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
        quotient: &mut [F],
    ) -> Result<(), Error>;

    /// The part of "r" that belongs to the widget
    /// The second return value is the constant term
    fn compute_linear_contribution(
        &self,
        prover: &mut Prover<F, D, E>,
        combinator: &mut F,
    ) -> Result<(LinearCombination<F>, F), Error>;
}
