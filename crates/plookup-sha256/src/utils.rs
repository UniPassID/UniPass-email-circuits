use ark_ff::{batch_inversion, PrimeField};
use ark_poly::Evaluations;
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, UVPolynomial};
use ark_std::rand::Rng;
use ark_std::{end_timer, start_timer};

pub use ark_ff::PrimeField as Field;

pub fn gen_verify_comms_labels(
    program_width: usize,
    contain_range: bool,
    contain_lookup: bool,
    contain_mimc: bool,
    contain_substring: bool,
    contain_pubmatch: bool,
) -> Vec<String> {
    let mut labels = vec![];
    for i in 0..program_width {
        let value = format!("q_{}", i);
        labels.push(value);
    }
    labels.push(format!("q_m"));
    labels.push(format!("q_c"));
    labels.push(format!("q0next"));
    labels.push(format!("q_arith"));
    if contain_lookup {
        labels.push(format!("q_lookup"));
        labels.push(format!("q_table"));
    }
    for i in 0..program_width {
        let value = format!("sigma_{}", i);
        labels.push(value);
    }
    if contain_lookup {
        for i in 0..program_width + 1 {
            let value = format!("table_{}", i);
            labels.push(value);
        }
    }

    if contain_range {
        labels.push(format!("q_range"));
    }
    if contain_substring {
        labels.push(format!("q_substring"));
        labels.push(format!("q_substring_r"));
    }
    if contain_pubmatch {
        labels.push(format!("q_pubmatch"));
    }
    if contain_mimc {
        labels.push(format!("q_mimc"));
    }

    labels
}

pub fn gen_verify_open_zeta_labels(
    program_width: usize,
    contain_lookup: bool,
    // contain_substring: bool,
) -> Vec<String> {
    let mut labels = vec![];
    labels.push(format!("t4t"));
    labels.push(format!("r"));
    for i in 0..program_width {
        let value = format!("w_{}", i);
        labels.push(value);
    }
    for i in 0..program_width - 1 {
        let value = format!("sigma_{}", i);
        labels.push(value);
    }
    labels.push(format!("q_arith"));
    if contain_lookup {
        labels.push(format!("q_table"));
        labels.push(format!("q_lookup"));
        labels.push(format!("table"));
    }

    labels
}

pub fn gen_verify_open_zeta_omega_labels(
    // program_width: usize,
    contain_lookup: bool,
    contain_substring: bool,
) -> Vec<String> {
    let mut labels = vec![];
    labels.push(format!("w_0"));
    labels.push(format!("z"));
    if contain_lookup {
        labels.push(format!("s"));
        labels.push(format!("z_lookup"));
        labels.push(format!("table"));
    }
    if contain_substring {
        labels.push(format!("w_1"));
        labels.push(format!("w_2"));
        labels.push(format!("w_3"));
        labels.push(format!("z_substring"));
    }

    labels
}

pub fn coset_generator<F: Field>(index: usize) -> F {
    match index {
        1 => F::from(7_u64),
        2 => F::from(13_u64),
        3 => F::from(17_u64),
        4 => F::from(23_u64),
        _ => F::one(),
    }
}

pub trait Domain<F: Field>: 'static + EvaluationDomain<F> {
    fn generator(&self) -> F {
        self.element(1)
    }

    fn vanishing_polynomial(self) -> DensePolynomial<F> {
        let n = self.size();
        let mut coeffs = vec![F::zero(); n + 1];
        coeffs[0] = -F::one();
        coeffs[n] = F::one();
        DensePolynomial::from_coefficients_vec(coeffs)
    }

    /// index in range [1, domain_size]
    fn lagrange_polynomial(self, index: usize) -> DensePolynomial<F> {
        let n = self.size();
        assert!(index >= 1 && index <= n);
        let mut coeffs = vec![F::zero(); n];
        coeffs[index - 1] = F::one();
        Evaluations::from_vec_and_domain(coeffs, self).interpolate()
    }

    /// index in range [1, domain_size]
    fn evaluate_lagrange_polynomial(&self, index: usize, point: &F) -> F {
        let n = self.size();
        assert!(index >= 1 && index <= n);
        let numerator = point.pow(&[n as u64]) - F::one();
        let denominator = (F::from(n as u64) * (self.element(n - index + 1) * point - F::one()))
            .inverse()
            .unwrap();
        numerator * denominator
    }

    fn batch_evaluate_lagrange_polynomial(&self, indices: Vec<usize>, point: &F) -> Vec<F> {
        let n = self.size();

        indices
            .iter()
            .copied()
            .for_each(|i| assert!(i >= 1 && i <= n));

        let mut denominators: Vec<_> = indices
            .into_iter()
            .map(|i| F::from(n as u64) * (self.element(n - i + 1) * point - F::one()))
            .collect();
        batch_inversion(&mut denominators);

        let numerator = point.pow(&[n as u64]) - F::one();

        denominators
            .into_iter()
            .map(|denominator| denominator * numerator)
            .collect()
    }
}

pub type GeneralEvaluationDomain<F> = ark_poly::GeneralEvaluationDomain<F>;
impl<F: Field> Domain<F> for GeneralEvaluationDomain<F> {}

pub(crate) fn interpolate_and_coset_fft<F: Field>(
    mut domain_values: Vec<F>,
    domain: impl Domain<F>,
    coset: impl Domain<F>,
) -> (Vec<F>, Vec<F>, DensePolynomial<F>) {
    let zeros = vec![F::zero(); domain.size() - domain_values.len()];
    domain_values.extend(zeros);

    let polynomial = Evaluations::from_vec_and_domain(domain_values.clone(), domain).interpolate();

    let coset_values = coset.coset_fft(&polynomial);
    (domain_values, coset_values, polynomial)
}

/// return domain_values, polynomial
pub(crate) fn padding_and_interpolate<F: Field>(
    mut domain_values: Vec<F>,
    domain: impl Domain<F>,
) -> (Vec<F>, DensePolynomial<F>) {
    let zeros = vec![F::zero(); domain.size() - domain_values.len()];
    domain_values.extend(zeros);

    let polynomial = Evaluations::from_vec_and_domain(domain_values.clone(), domain).interpolate();

    (domain_values, polynomial)
}

/// open_num: num of points this poly would be opened (now 1 or 2)
/// return blind coset_values, polynomial
pub(crate) fn blind_and_coset_fft<F: Field, R: Rng>(
    mut polynomial: DensePolynomial<F>,
    domain: impl Domain<F>,
    coset: impl Domain<F>,
    open_num: usize,
    rng: &mut R,
) -> (Vec<F>, DensePolynomial<F>) {
    assert!(open_num > 0);
    let mut blind_coeffs = vec![F::rand(rng)];
    for _ in 0..open_num {
        blind_coeffs.push(F::rand(rng));
    }

    let blind_polynomial =
        DensePolynomial::from_coefficients_vec(blind_coeffs).mul_by_vanishing_poly(domain);
    // let vi = domain.vanishing_polynomial();
    // let blind_polynomial = DensePolynomial::from_coefficients_vec(blind_coeffs).mul(&vi);

    polynomial += &blind_polynomial;

    let coset_values = coset.coset_fft(&polynomial);
    (coset_values, polynomial)
}

/// special handle for t poly
pub(crate) fn blind_t<F: Field, R: Rng>(
    mut polynomials: Vec<DensePolynomial<F>>,
    domain: impl Domain<F>,
    rng: &mut R,
) -> Vec<DensePolynomial<F>> {
    assert!(polynomials.len() >= 3);
    let len = polynomials.len();
    let mut blind_rand = vec![];
    for _ in 0..len - 1 {
        blind_rand.push(F::rand(rng));
    }

    let tmp_coeff = vec![F::zero(); domain.size()];

    let mut coeff0 = tmp_coeff.clone();
    coeff0.push(blind_rand[0]);
    polynomials[0] += &DensePolynomial::from_coefficients_vec(coeff0);

    for i in 1..len - 1 {
        let mut coeff = tmp_coeff.clone();
        coeff.push(blind_rand[i]);
        coeff[0] = -blind_rand[i - 1];

        polynomials[i] += &DensePolynomial::from_coefficients_vec(coeff);
    }

    polynomials[len - 1] += &DensePolynomial::from_coefficients_vec(vec![-blind_rand[len - 2]]);

    polynomials
}

pub fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    use rayon::iter::IntoParallelRefIterator;
    use rayon::iter::ParallelIterator;

    let to_bigint_time = start_timer!(|| "Converting polynomial coeffs to bigints");
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_repr())
        .collect::<Vec<_>>();
    end_timer!(to_bigint_time);
    coeffs
}

#[cfg(test)]
mod tests {
    // use ark_bls12_381::{Bls12_381, Fr};
    use ark_bn254::Fr;

    use ark_poly::Polynomial;
    use ark_std::{rand::Rng, test_rng, UniformRand};
    use num_bigint::BigUint;

    use super::*;

    #[test]
    fn test_fr() {
        let m = Fr::from(BigUint::parse_bytes(b"42649378395939397566720", 10).unwrap());
        println!("{}", m.into_repr());
    }

    #[test]
    fn utils_lagrange_evaluation() {
        let rng = &mut test_rng();
        let size: usize = rng.gen_range(1..(2 as usize).pow(10));
        let domain = GeneralEvaluationDomain::<Fr>::new(size).unwrap();
        let index = rng.gen_range(1..domain.size() + 1);
        let point = Fr::rand(rng);

        let l = domain.lagrange_polynomial(index);
        let l_point = domain.evaluate_lagrange_polynomial(index, &point);

        println!(
            "{}-th lagrange polynomial for domain of size {}:",
            index,
            domain.size()
        );
        assert_eq!(l.evaluate(&point), l_point);
    }

    #[test]
    fn utils_batch_lagrange_evaluation() {
        let rng = &mut test_rng();
        let size: usize = rng.gen_range(1..(2 as usize).pow(10));
        let domain = GeneralEvaluationDomain::<Fr>::new(size).unwrap();
        let batch_size = 32;
        let indices: Vec<_> = (0..batch_size)
            .into_iter()
            .map(|_| rng.gen_range(1..domain.size() + 1))
            .collect();
        let point = Fr::rand(rng);
        let evaluations = domain.batch_evaluate_lagrange_polynomial(indices.clone(), &point);

        indices.iter().enumerate().for_each(|(i, &j)| {
            assert_eq!(
                evaluations[i],
                domain.evaluate_lagrange_polynomial(j, &point)
            )
        });
    }
}
