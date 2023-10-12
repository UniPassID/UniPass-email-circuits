use plonk::{
    ark_ff::PrimeField,
    composer::Variable,
    sha256::{sha256_no_padding_words_var, Sha256Word},
    Composer, Error,
};

use crate::utils::padding_bytes;

pub fn one_bit_vector<F: PrimeField>(
    cs: &mut Composer<F>,
    n: usize,
    index_var: Variable,
) -> Vec<Variable> {
    let index = {
        let index_value = cs.get_assignment(index_var);
        let tmp = index_value.into_repr();
        tmp.as_ref()[0]
    };
    let mut outputs = vec![];
    let mut lc = Composer::<F>::null();
    for i in 0..n {
        let tmp = if i as u64 == index { 1u64 } else { 0u64 };
        let tmp = cs.alloc(F::from(tmp));

        let i_var = cs.alloc(F::from(i as u64));
        cs.enforce_constant(i_var, F::from(i as u64));

        let index_minus_i_var = cs.sub(index_var, i_var);
        cs.poly_gate(
            vec![(tmp, F::zero()), (index_minus_i_var, F::zero())],
            F::one(),
            F::zero(),
        );
        lc = cs.add(lc, tmp);

        outputs.push(tmp);
    }

    cs.enforce_constant(lc, F::one());
    outputs
}

// fn gt_bit_vector<F: PrimeField>(
//     cs: &mut Composer<F>,
//     n: usize,
//     index_var: Variable,
// ) -> Result<Vec<Variable>, Error> {
//     todo!()
// }

pub fn lt_bit_vector<F: PrimeField>(
    cs: &mut Composer<F>,
    n: usize,
    index_var: Variable,
) -> Vec<Variable> {
    let index = {
        let index_value = cs.get_assignment(index_var);
        let tmp = index_value.into_repr();
        tmp.as_ref()[0]
    };
    let index_minus_1 = index - 1;
    let index_minus_1_var = cs.alloc(F::from(index_minus_1));
    cs.poly_gate(
        vec![(index_var, F::one()), (index_minus_1_var, -F::one())],
        F::zero(),
        -F::one(),
    );
    let eq = one_bit_vector(cs, n, index_minus_1_var);
    let mut outputs = vec![];
    outputs.push(eq[n - 1]);
    for i in 0..n - 1 {
        outputs.push(cs.add(eq[n - 2 - i], outputs[i]))
    }

    outputs.reverse();
    outputs
}

pub fn sha256_var<F: PrimeField>(
    cs: &mut Composer<F>,
    input_bytes: &[u8],
    max_len: usize,
) -> Result<(Vec<Variable>, Vec<Variable>), Error> {
    let input_padding_bytes = padding_bytes(input_bytes);
    let input_padding_len = (input_padding_bytes.len() / 64) as u32;

    let mut input_padding_vars = vec![];
    for e in &input_padding_bytes {
        input_padding_vars.push(cs.alloc(F::from(*e)));
    }
    let n = input_padding_vars.len();
    for _ in n..max_len {
        input_padding_vars.push(cs.alloc(F::zero()));
    }

    println!(
        "input_padding_len: {}-{}",
        input_bytes.len(),
        input_padding_len
    );

    // num of 512bits. we need the index to output correct sha256.
    let input_data_len = cs.alloc(F::from(input_padding_len));

    let mut sha256_input_data = vec![];
    for vs in input_padding_vars.chunks(4) {
        // "Sha256Word" is the type we need in the sha256, each contain 32bits
        sha256_input_data.push(Sha256Word::new_from_8bits(cs, vs[0], vs[1], vs[2], vs[3]).unwrap());
    }

    // get the input hash
    Ok((
        input_padding_vars,
        sha256_no_padding_words_var(cs, &sha256_input_data, input_data_len, max_len * 8 / 512)?,
    ))
}

pub fn enforce_eq_before_index<F: PrimeField>(
    cs: &mut Composer<F>,
    n: usize,
    index_var: Variable,
    a: &[Variable],
    b: &[Variable],
) {
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);

    let eq = lt_bit_vector(cs, n, index_var);
    for i in 0..n {
        let ci = cs.sub(a[i], b[i]);
        cs.mul_gate(ci, eq[i], Composer::<F>::null());
    }
}

/// ensure some positions are matched between "a" and "b". "b" is a public string.
/// if any var is 0 in "b", we default that this byte is private (not match), otherwise must match to "a"
pub fn public_match_before_index<F: PrimeField>(
    cs: &mut Composer<F>,
    n: usize,
    index_var: Variable,
    a: &Vec<Variable>,
    b: &Vec<Variable>,
) {
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);

    let eq = lt_bit_vector(cs, n, index_var);
    // prove public_match
    // b * (a - b) * eq === 0
    for i in 0..n {
        let ci = cs.sub(a[i], b[i]);
        let tmp = cs.mul(eq[i], b[i]);
        cs.mul_gate(ci, tmp, Composer::<F>::null());
    }

    // recommend hash "b" to compress public_input
}
