use std::collections::BTreeMap;

use plonk::{
    ark_ff::PrimeField,
    composer::{Table, Variable},
    Composer, Error,
};

pub const BASE64URL_ENCODE_CHARS: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn get_encoded_len(input_len: usize) -> usize {
    let mut encoded_len = input_len / 3 * 4;
    if input_len % 3 == 1 {
        encoded_len += 2;
    } else if input_len % 3 == 2 {
        encoded_len += 3;
    }

    encoded_len
}

pub fn new_baseurl_chars_table<F: PrimeField>() -> Table<F> {
    let size = 64;
    let width = 2;
    let key_width = 1; //key is num

    let mut columns = vec![Vec::with_capacity(size); width];
    let mut key_map = BTreeMap::new();
    let mut row = 0;
    for key in 0..size {
        for (i, v) in vec![
            F::from(key as u64),
            F::from(BASE64URL_ENCODE_CHARS[key] as u64),
        ]
        .into_iter()
        .enumerate()
        {
            columns[i].push(v);
        }

        key_map.insert(vec![F::from(key as u64)], row);
        row += 1;
    }

    Table {
        id: "base64url_chars".to_string(),
        index: 0,
        size,
        width,
        key_width,
        columns,
        lookups: Vec::new(),

        key_map,
    }
}

pub fn new_baseurl_decode_chars_table<F: PrimeField>() -> Table<F> {
    let size = 256; // table size
    let chars_size = 64; // base64url chars size
    let width = 3; // total width
    let key_width = 1; //key's num

    let mut is_base64url_chars = vec![false; 256];

    let mut columns = vec![Vec::with_capacity(size); width];
    let mut key_map = BTreeMap::new();
    let mut row = 0;
    for key in 0..chars_size {
        for (i, v) in vec![
            F::from(BASE64URL_ENCODE_CHARS[key] as u64),
            F::from(key as u64),
            F::from(0 as u64),
        ]
        .into_iter()
        .enumerate()
        {
            columns[i].push(v);
        }

        is_base64url_chars[BASE64URL_ENCODE_CHARS[key] as usize] = true;

        key_map.insert(vec![F::from(BASE64URL_ENCODE_CHARS[key] as u64)], row);
        row += 1;
    }

    let not_base64url_chars = is_base64url_chars
        .into_iter()
        .enumerate()
        .filter(|v| v.1 == false)
        .map(|v| v.0 as u64)
        .collect::<Vec<_>>();

    for key in not_base64url_chars {
        for (i, v) in vec![F::from(key), F::from(0 as u64), F::from(1 as u64)]
            .into_iter()
            .enumerate()
        {
            columns[i].push(v);
        }

        key_map.insert(vec![F::from(key)], row);
        row += 1;
    }

    Table {
        id: "base64url_decode_chars".to_string(),
        index: 0,
        size,
        width,
        key_width,
        columns,
        lookups: Vec::new(),
        key_map,
    }
}

/// generate "bits_location", 1 Variable represent 1 bit
/// max_lens, b_max_lens must be a multiple of 32.
pub fn base64url_decode_gadget<F: PrimeField>(
    cs: &mut Composer<F>,
    input_messages: &[Variable],
    num_limit: usize,
) -> Result<Vec<Variable>, Error> {
    assert_eq!(input_messages.len(), num_limit);
    assert!(num_limit % 4 == 0);
    let mut outputs = vec![];
    let base64url_decode_index = cs.add_table(new_baseurl_decode_chars_table());
    assert!(base64url_decode_index != 0);

    let spread2_index = cs.get_table_index("spread_2bits".to_string());
    assert!(spread2_index != 0);
    let spread_4_index = cs.get_table_index("spread_5bits_4bits".to_string());
    assert!(spread_4_index != 0);

    for chars in input_messages.chunks(4) {
        let index_1_var = cs.read_from_table(base64url_decode_index, vec![chars[0]])?;
        let index_2_var = cs.read_from_table(base64url_decode_index, vec![chars[1]])?;
        let index_3_var = cs.read_from_table(base64url_decode_index, vec![chars[2]])?;
        let index_4_var = cs.read_from_table(base64url_decode_index, vec![chars[3]])?;

        let index_1_value = cs.get_assignments(&index_1_var);
        let index_1 = {
            let tmp = index_1_value[0].into_repr();
            tmp.as_ref()[0]
        };
        let index_2_value = cs.get_assignments(&index_2_var);
        let index_2 = {
            let tmp = index_2_value[0].into_repr();
            tmp.as_ref()[0]
        };
        let index_2_1 = index_2 >> 4;
        let index_2_2 = index_2 & 0xf;

        let index_2_1_var = cs.alloc(F::from(index_2_1));
        let _ = cs.read_from_table(spread2_index, vec![index_2_1_var])?;

        let index_2_2_var = cs.alloc(F::from(index_2_2));
        let _ = cs.read_from_table(spread_4_index, vec![index_2_2_var, Composer::<F>::null()])?;

        cs.poly_gate(
            vec![
                (index_2_var[0], -F::one()),
                (index_2_1_var, F::from(1u64 << 4)),
                (index_2_2_var, F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        let index_3_value = cs.get_assignments(&index_3_var);
        let index_3 = {
            let tmp = index_3_value[0].into_repr();
            tmp.as_ref()[0]
        };

        let index_3_1 = index_3 >> 2;
        let index_3_2 = index_3 & 0x3;

        let index_3_1_var = cs.alloc(F::from(index_3_1));
        let _ = cs.read_from_table(spread_4_index, vec![index_3_1_var, Composer::<F>::null()])?;
        let index_3_2_var = cs.alloc(F::from(index_3_2));
        let _ = cs.read_from_table(spread2_index, vec![index_3_2_var])?;

        cs.poly_gate(
            vec![
                (index_3_var[0], -F::one()),
                (index_3_1_var, F::from(1u64 << 2)),
                (index_3_2_var, F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        let index_4_value = cs.get_assignments(&index_4_var);
        let index_4 = {
            let tmp = index_4_value[0].into_repr();
            tmp.as_ref()[0]
        };

        let output_1 = (index_1 << 2) + index_2_1;
        let output_1_var = cs.alloc(F::from(output_1));
        cs.poly_gate(
            vec![
                (output_1_var, -F::one()),
                (index_1_var[0], F::from(1u64 << 2)),
                (index_2_1_var, F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        let output_2 = (index_2_2 << 4) + index_3_1;
        let output_2_var = cs.alloc(F::from(output_2));
        cs.poly_gate(
            vec![
                (output_2_var, -F::one()),
                (index_2_2_var, F::from(1u64 << 4)),
                (index_3_1_var, F::one()),
            ],
            F::zero(),
            F::zero(),
        );
        let output_3 = (index_3_2 << 6) + index_4;
        let output_3_var = cs.alloc(F::from(output_3));
        cs.poly_gate(
            vec![
                (output_3_var, -F::one()),
                (index_3_2_var, F::from(1u64 << 6)),
                (index_4_var[0], F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        outputs.push(output_1_var);
        outputs.push(output_2_var);
        outputs.push(output_3_var);
    }

    Ok(outputs)
}

/// generate "bits_location", 1 Variable represent 1 bit
/// max_lens, b_max_lens must be a multiple of 32.
pub fn base64url_encode_gadget<F: PrimeField>(
    cs: &mut Composer<F>,
    input_messages: &[Variable],
    num_limit: usize,
) -> Result<Vec<Variable>, Error> {
    assert_eq!(input_messages.len(), num_limit);
    assert!(num_limit % 3 == 0);
    let mut output = vec![];
    let base64url_index = cs.add_table(new_baseurl_chars_table());
    assert!(base64url_index != 0);

    let spread2_index = cs.get_table_index("spread_2bits".to_string());
    assert!(spread2_index != 0);
    let spread_4_index = cs.get_table_index("spread_5bits_4bits".to_string());
    assert!(spread_4_index != 0);
    let spread_6_index = cs.get_table_index("spread_7bits_6bits".to_string());
    assert!(spread_6_index != 0);

    for chars in input_messages.chunks(3) {
        let chars_value = cs.get_assignments(chars);
        let char1 = {
            let tmp = chars_value[0].into_repr();
            tmp.as_ref()[0]
        };
        let char2 = {
            let tmp = chars_value[1].into_repr();
            tmp.as_ref()[0]
        };
        let char3 = {
            let tmp = chars_value[2].into_repr();
            tmp.as_ref()[0]
        };

        let char1_1 = char1 >> 2;
        let char1_1_var = cs.alloc(F::from(char1_1));
        let _ = cs.read_from_table(spread_6_index, vec![char1_1_var, Composer::<F>::null()])?;

        let char1_2 = char1 & 0x3;
        let char1_2_var = cs.alloc(F::from(char1_2));
        let _ = cs.read_from_table(spread2_index, vec![char1_2_var])?;

        let char2_1 = char2 >> 4;
        let char2_1_var = cs.alloc(F::from(char2_1));
        let _ = cs.read_from_table(spread_4_index, vec![char2_1_var, Composer::<F>::null()])?;

        let char2_2 = char2 & 0xf;
        let char2_2_var = cs.alloc(F::from(char2_2));
        let _ = cs.read_from_table(spread_4_index, vec![char2_2_var, Composer::<F>::null()])?;

        let char3_1 = char3 >> 6;
        let char3_1_var = cs.alloc(F::from(char3_1));
        let _ = cs.read_from_table(spread2_index, vec![char3_1_var])?;

        let char3_2 = char3 & 0x3f;
        let char3_2_var = cs.alloc(F::from(char3_2));
        let _ = cs.read_from_table(spread_6_index, vec![char3_2_var, Composer::<F>::null()])?;

        cs.poly_gate(
            vec![
                (chars[0], -F::one()),
                (char1_1_var, F::from(1u64 << 2)),
                (char1_2_var, F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        cs.poly_gate(
            vec![
                (chars[1], -F::one()),
                (char2_1_var, F::from(1u64 << 4)),
                (char2_2_var, F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        cs.poly_gate(
            vec![
                (chars[2], -F::one()),
                (char3_1_var, F::from(1u64 << 6)),
                (char3_2_var, F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        let out1_var = char1_1_var;
        let out2_var = cs.alloc(F::from((char1_2 << 4) + char2_1));
        let out3_var = cs.alloc(F::from((char2_2 << 2) + char3_1));
        let out4_var = char3_2_var;

        cs.poly_gate(
            vec![
                (out2_var, -F::one()),
                (char1_2_var, F::from(1u64 << 4)),
                (char2_1_var, F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        cs.poly_gate(
            vec![
                (out3_var, -F::one()),
                (char2_2_var, F::from(1u64 << 2)),
                (char3_1_var, F::one()),
            ],
            F::zero(),
            F::zero(),
        );

        let output_var1 = cs.read_from_table(base64url_index, vec![out1_var])?;
        output.push(output_var1[0]);

        let output_var2 = cs.read_from_table(base64url_index, vec![out2_var])?;
        output.push(output_var2[0]);

        let output_var3 = cs.read_from_table(base64url_index, vec![out3_var])?;
        output.push(output_var3[0]);

        let output_var4 = cs.read_from_table(base64url_index, vec![out4_var])?;
        output.push(output_var4[0]);
    }

    Ok(output)
}

// enforce encode_len is the base64url_encoded length of datalen
// simple it to (data_len * 4 - encoded_len * 3) * ((data_len * 4  - (encoded_len * 3 -1)) * ((data_len * 4  - (encoded_len * 3 -2)) = 0
pub fn enforce_encoded_len<F: PrimeField>(
    cs: &mut Composer<F>,
    data_len: Variable,
    encoded_len: Variable,
) -> Result<(), Error> {
    let four_var = cs.alloc(F::from(4u64));
    cs.enforce_constant(four_var, F::from(4u64));
    let three_var = cs.alloc(F::from(3u64));
    cs.enforce_constant(three_var, F::from(3u64));
    let two_var = cs.alloc(F::from(2u64));
    cs.enforce_constant(two_var, F::from(2u64));
    let one_var = cs.alloc(F::from(1u64));
    cs.enforce_constant(one_var, F::from(1u64));

    let encoded_len_mul_3 = cs.mul(encoded_len, three_var);
    let data_len_mul_4 = cs.mul(data_len, four_var);

    let tmp1 = cs.sub(data_len_mul_4, encoded_len_mul_3);

    let tmp2_1 = cs.sub(encoded_len_mul_3, one_var);
    let tmp2 = cs.sub(data_len_mul_4, tmp2_1);

    let tmp3_1 = cs.sub(encoded_len_mul_3, two_var);
    let tmp3 = cs.sub(data_len_mul_4, tmp3_1);

    let tmp4 = cs.mul(tmp1, tmp2);
    let tmp5 = cs.mul(tmp3, tmp4);

    cs.enforce_eq(tmp5, Composer::<F>::null());

    Ok(())
}

pub fn variable_to_u64<F: PrimeField>(cs: &Composer<F>, v: Variable) -> u64 {
    let value = cs.get_assignment(v);
    value.into_repr().as_ref()[0]
}
