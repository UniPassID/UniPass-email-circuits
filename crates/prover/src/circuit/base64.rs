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
            F::from(BASE64URL_ENCODE_CHARS[key as usize] as u64),
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
        id: format!("base64urlchars"),
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

    let spread2_index = cs.get_table_index(format!("spread_2bits"));
    assert!(spread2_index != 0);
    let spread_4_index = cs.get_table_index(format!("spread_5bits_4bits"));
    assert!(spread_4_index != 0);
    let spread_6_index = cs.get_table_index(format!("spread_7bits_6bits"));
    assert!(spread_6_index != 0);

    for chars in input_messages.chunks(3) {
        let chars_value = cs.get_assignments(chars);
        let char1 = {
            let tmp = chars_value[0].into_repr();
            tmp.as_ref()[0].clone()
        };
        let char2 = {
            let tmp = chars_value[1].into_repr();
            tmp.as_ref()[0].clone()
        };
        let char3 = {
            let tmp = chars_value[2].into_repr();
            tmp.as_ref()[0].clone()
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
        let out2_var = cs.alloc(F::from(char1_2 * (1 << 4) + char2_1));
        let out3_var = cs.alloc(F::from(char2_2 * (1 << 2) + char3_1));
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

    return Ok(output);
}
