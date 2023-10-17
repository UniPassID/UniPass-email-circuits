use plonk::{
    ark_ff::PrimeField,
    composer::Variable,
    sha256::{num_to_selectors, sha256_no_padding_words_var, Sha256Word},
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

    for i in 0..n {
        let tmp = if i as u64 == index { 1u64 } else { 0u64 };
        let tmp = cs.alloc(F::from(tmp));
        cs.enforce_bool(tmp);

        cs.poly_gate(
            vec![(tmp, -F::from(i as u128)), (index_var, F::zero())],
            F::one(),
            F::zero(),
        );

        outputs.push(tmp);
    }

    let mut lc = outputs[0];
    for i in 1..n {
        lc = cs.add(lc, outputs[i]);
    }

    cs.enforce_constant(lc, F::one());
    outputs
}

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
    let eqs = num_to_selectors(cs, index_minus_1_var, n);
    let mut outputs = vec![];
    outputs.push(eqs[n - 1]);
    for i in 0..n - 1 {
        outputs.push(cs.add(eqs[n - 2 - i], outputs[i]))
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

    for i in 0..n {
        let lts = lt_bit_vector(cs, n, index_var);
        let ci = cs.sub(a[i], b[i]);
        cs.mul_gate(ci, lts[i], Composer::<F>::null());
    }
}

/// ensure some positions are matched between "a" and "b". "b" is a public string.
/// if any var is 0 in "b", we default that this byte is private (not match), otherwise must match to "a"
pub fn public_match_before_index<F: PrimeField>(
    cs: &mut Composer<F>,
    n: usize,
    index_var: Variable,
    a: &[Variable],
    b: &[Variable],
) {
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);

    let lts = lt_bit_vector(cs, n, index_var);
    // prove public_match
    // b * (a - b) * eq === 0
    for i in 0..n {
        let ci = cs.sub(a[i], b[i]);
        let tmp = cs.mul(lts[i], b[i]);
        cs.mul_gate(ci, tmp, Composer::<F>::null());
    }
}

pub fn log2(input: u64) -> u64 {
    if input == 0 {
        return 0;
    }
    let mut n = 1;
    let mut r = 1;
    while n < input {
        r += 1;
        n *= 2;
    }
    return r;
}

pub fn num_to_bits<F: PrimeField>(
    cs: &mut Composer<F>,
    n: usize,
    input_var: Variable,
) -> Vec<Variable> {
    let mut outputs = vec![];
    let mut lc1 = Composer::<F>::null();
    let mut e2 = cs.alloc(F::one());
    cs.enforce_constant(e2, F::one());

    let input = {
        let input_value = cs.get_assignment(input_var);
        let tmp = input_value.into_repr();
        tmp.as_ref()[0]
    };

    for i in 0..n {
        outputs.push(cs.alloc(F::from((input >> i) & 1)));
        cs.enforce_bool(outputs[i]);

        let tmp = cs.mul(outputs[i], e2);
        lc1 = cs.add(lc1, tmp);
        e2 = cs.add(e2, e2)
    }
    cs.enforce_eq(input_var, lc1);
    outputs
}

pub fn slice_shift_left<F: PrimeField>(
    cs: &mut Composer<F>,
    max_slice_len: usize,
    max_sub_slice_len: usize,
    index_var: Variable,
    slice: &[Variable],
) -> Vec<Variable> {
    let mut outs = vec![];
    let eqs = one_bit_vector(cs, max_slice_len, index_var);
    for i in 0..max_sub_slice_len {
        let mut arr = vec![];
        for j in 0..max_slice_len {
            if j < i {
                arr.push(Composer::<F>::null())
            } else {
                arr.push(eqs[j - i])
            }
        }

        let mut lc = Composer::<F>::null();
        for i in 0..max_slice_len {
            let tmp = cs.mul(arr[i], slice[i]);
            lc = cs.add(lc, tmp)
        }

        outs.push(lc)
    }

    outs
}

pub fn slice_shift_left_efficent<F: PrimeField>(
    cs: &mut Composer<F>,
    max_input_len: usize,
    max_output_len: usize,
    index_var: Variable,
    slice: &[Variable],
) -> Vec<Variable> {
    let len_bits = log2(max_input_len as u64);
    let n2b = num_to_bits(cs, len_bits as usize, index_var);
    let mut outs = vec![];

    let mut tmp = vec![];
    for j in 0..len_bits as usize {
        tmp.push(vec![]);
        for i in 0..max_input_len {
            let offset = (i + (1 << j)) % max_input_len;
            if j == 0 {
                let tmp1 = cs.sub(slice[offset], slice[i]);
                let tmp2 = cs.mul(n2b[j], tmp1);
                let tmp3 = cs.add(tmp2, slice[i]);
                tmp[j].push(tmp3);
            } else {
                let tmp1 = cs.sub(tmp[j - 1][offset], tmp[j - 1][i]);
                let tmp2 = cs.mul(n2b[j], tmp1);
                let tmp3 = cs.add(tmp2, tmp[j - 1][i]);
                tmp[j].push(tmp3);
            }
        }
    }

    for i in 0..max_output_len {
        outs.push(tmp[len_bits as usize - 1][i])
    }

    outs
}

pub fn sub_slice_check<F: PrimeField>(
    cs: &mut Composer<F>,
    max_slice_len: usize,
    max_sub_slice_len: usize,
    slice: &Vec<Variable>,
    sub_slice: &Vec<Variable>,
    from_index: Variable,
    length: Variable,
) {
    let shifted_slice =
        slice_shift_left_efficent(cs, max_slice_len, max_sub_slice_len, from_index, slice);

    enforce_eq_before_index(cs, max_sub_slice_len, length, sub_slice, &shifted_slice);
}
