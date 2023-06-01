use ark_serialize::*;
use ark_std::{cfg_iter, cfg_iter_mut, cmp::max, format, vec, vec::Vec};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::prover::ProverKey;
use crate::{Domain, Error, Field, Map};

mod arithmetic;
mod lookup;
mod permutation;
pub use lookup::Table;
mod mimc;
mod range;
mod substring;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct Wire {
    pub col: usize,
    pub row: usize,
}

impl Wire {
    fn new(col: usize, row: usize) -> Self {
        Self { col, row }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash, Ord, PartialOrd, Default)]
pub struct Variable(usize);

#[derive(Debug, Default, Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct ComposerConfig {
    pub enable_q0next: bool,
    pub enable_range: bool,
    pub enable_lookup: bool,
    pub enable_mimc: bool,
    pub enable_private_substring: bool,
    pub enable_pubmatch: bool,
}

#[derive(Debug, Default)]
pub struct SimpleUnionFind {
    // store parent
    disjoint: Vec<usize>,
    // height of tree
    rank: Vec<usize>,
}

impl SimpleUnionFind {
    pub fn size(&self) -> usize {
        self.disjoint.len()
    }

    pub fn append(&mut self) {
        let size = self.disjoint.len();
        self.disjoint.push(size);

        self.rank.push(1);
    }

    pub fn find(&mut self, x: usize) -> usize {
        if x == self.disjoint[x] {
            x
        } else {
            self.disjoint[x] = self.find(self.disjoint[x]);
            self.disjoint[x]
        }
    }

    pub fn is_connected(&mut self, x: usize, y: usize) -> bool {
        let root_x = self.find(x);
        let root_y = self.find(y);
        root_x == root_y
    }

    pub fn union(&mut self, x: usize, y: usize) {
        let root_x = self.find(x);
        let root_y = self.find(y);
        if root_x != root_y {
            if self.rank[root_x] < self.rank[root_y] {
                self.disjoint[root_x] = root_y;
            } else {
                self.disjoint[root_y] = root_x;
                if self.rank[root_x] == self.rank[root_y] {
                    self.rank[root_y] += 1;
                }
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct Composer<F: Field> {
    // number of witness columns of the circuit
    pub program_width: usize,
    // rows of the circuit
    size: usize,
    is_finalized: bool,

    // witness columns
    wires: Map<String, Vec<Variable>>,
    selectors: Map<String, Vec<F>>,
    public_input: Vec<Variable>,

    // value in the Variable
    assignments: Vec<F>,
    // permutation info
    epicycles: Vec<Vec<Wire>>,
    // eq constraints between Variables
    eq_constraints: SimpleUnionFind,

    // tables for lookup
    tables: Vec<Table<F>>,

    // custom gates
    pub switches: ComposerConfig,
}

/// basics
impl<F: Field> Composer<F> {
    const SELECTOR_LABELS: [&'static str; 4] = ["q_m", "q_c", "q_lookup", "q_table"];

    /// new circuit of "program_width" column witness
    pub fn new(program_width: usize, enable_q0next: bool) -> Composer<F> {
        let mut cs = Composer::default();

        for j in 0..program_width {
            cs.wires.insert(format!("w_{}", j), Vec::new());
            cs.selectors.insert(format!("q_{}", j), Vec::new());
        }
        for label in Self::SELECTOR_LABELS {
            cs.selectors.insert(label.to_string(), Vec::new());
        }
        if enable_q0next {
            cs.switches.enable_q0next = true;
            cs.selectors.insert("q0next".to_string(), Vec::new());
        }
        cs.program_width = program_width;

        // any()
        let _ = cs.alloc(F::zero());

        let null = cs.alloc(F::zero());
        cs.enforce_constant(null, F::zero());

        cs
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// public_input size
    #[inline]
    pub fn input_size(&self) -> usize {
        self.public_input.len()
    }

    /// alloc a variable
    pub fn alloc(&mut self, value: F) -> Variable {
        self.alloc_variable(value)
    }

    ///alloc a public input variable
    pub fn alloc_input(&mut self, value: F) -> Variable {
        let var = self.alloc_variable(value);
        self.public_input.push(var);

        var
    }

    /// set a variable public input
    pub fn set_variable_public_input(&mut self, var: Variable) {
        self.public_input.push(var);
    }

    /// const 0
    pub fn null() -> Variable {
        Variable(0)
    }

    #[inline]
    fn alloc_variable(&mut self, value: F) -> Variable {
        let var = Variable(self.epicycles.len());
        //each variable have an epicycles (copy constraint)
        self.epicycles.push(Vec::new());
        self.assignments.push(value);

        self.eq_constraints.append();

        var
    }

    #[inline]
    /// add a row. only fill witnesses. others are all 0, should be modified by calling function
    fn insert_gate(&mut self, mut gate_wires: Vec<Variable>) -> usize {
        assert!(gate_wires.len() <= self.program_width);
        while gate_wires.len() < self.program_width {
            gate_wires.push(Self::null());
        }

        for (_, values) in &mut self.selectors {
            values.push(F::zero());
        }

        let i = self.size;
        for j in 0..self.program_width {
            let wire_label = format!("w_{}", j);
            self.wires.get_mut(&wire_label).unwrap().push(gate_wires[j]);
            self.epicycles[gate_wires[j].0].push(Wire::new(j, i));
        }

        self.size += 1;

        i
    }

    /// get values of vars
    pub fn get_assignments(&self, vars: &[Variable]) -> Vec<F> {
        cfg_iter!(vars).map(|&v| self.assignments[v.0]).collect()
    }

    /// get value of var
    pub fn get_assignment(&self, var: Variable) -> F {
        self.assignments[var.0]
    }
}

/// synthesis
impl<F: Field> Composer<F> {
    /// pre-process polys of the circuit (q, sigma, table), reduce prove work.
    /// After the completion of circuit.
    pub fn compute_prover_key<D: Domain<F>>(&mut self) -> Result<ProverKey<F, D>, Error> {
        self.finalize();

        let size = max(self.size(), self.sorted_size());

        let mut prover_key =
            ProverKey::new(size, self.input_size(), self.program_width, self.switches)?;

        for (k, q) in self.selectors.iter() {
            prover_key.insert(k, q.clone());
        }

        let sigmas = self.compute_sigmas(prover_key.domain);
        for (col, sigma) in sigmas.iter().enumerate() {
            prover_key.insert(&format!("sigma_{}", col), sigma.clone());
        }

        // the last column for table indices
        let table_values = self.compute_table_values();
        for (col, table_value) in table_values.iter().enumerate() {
            prover_key.insert(&format!("table_{}", col), table_value.clone());
        }

        Ok(prover_key)
    }

    /// do this only after the completion of circuit.
    pub fn compute_public_input(&mut self) -> Vec<F> {
        self.finalize();

        cfg_iter!(self.public_input)
            .map(|v| self.assignments[v.0])
            .collect()
    }

    pub(crate) fn compute_wire_values(
        &mut self,
    ) -> Result<(Map<String, Vec<F>>, Map<String, Vec<F>>), Error> {
        self.finalize();

        let mut wires = Map::new();

        let assign = |v: &Variable| self.assignments[v.0];
        for (l, w) in self.wires.iter() {
            wires.insert(l.to_string(), cfg_iter!(w).map(assign).collect());
        }
        let sorted_values = self.compute_sorted_values();

        let mut swires = Map::new();
        for (col, sorted_value) in sorted_values.iter().enumerate() {
            swires.insert(format!("s_{}", col), sorted_value.clone());
        }

        Ok((wires, swires))
    }

    /// put PI into the circuit
    fn finalize(&mut self) {
        if self.is_finalized {
            return;
        };

        let input_size = self.input_size();
        self.size += input_size;

        self.epicycles.iter_mut().for_each(|epicycle| {
            cfg_iter_mut!(epicycle).for_each
                //Move all wires down 'input size' lines
                (|w| *w = Wire::new(w.col, w.row + input_size))
        });

        for (i, var) in self.public_input.iter().enumerate() {
            self.epicycles[var.0].push(Wire::new(0, i));
            for col in 1..self.program_width {
                // other witnesses just set 0 at PI' row
                self.epicycles[Self::null().0].push(Wire::new(col, i));
            }
        }

        // handle eq constraints
        self.handle_eq_constraints();

        let public_input = self.public_input.clone();
        //put PI at the front of w_0, q0 must be 1 and other 'q' must be 0.
        self.wires.iter_mut().for_each(|(label, wire)| {
            let mut vars = if label == "w_0" {
                public_input.clone()
            } else {
                vec![Self::null(); input_size]
            };
            vars.append(wire);
            std::mem::swap(wire, &mut vars)
        });

        self.selectors.iter_mut().for_each(|(label, selector)| {
            let mut values = if label == "q_0" {
                vec![F::one(); input_size]
            } else {
                vec![F::zero(); input_size]
            };
            values.append(selector);
            std::mem::swap(selector, &mut values)
        });

        self.is_finalized = true;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::{kzg10::PCKey, verifier::Verifier, *};
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};
    use ark_std::test_rng;
    use num_bigint::BigUint;

    fn composer_basic(cs: &mut Composer<Fr>) {
        // x^3 + x + pi = 35
        let pi = cs.alloc_input(Fr::from(5_u64));
        let x = cs.alloc(Fr::from(3));
        let y = cs.mul(x, x);
        let z = cs.mul(x, y);
        let u = cs.add(x, z);
        let v = cs.add(pi, u);
        cs.enforce_constant(v, Fr::from(BigUint::parse_bytes(b"23", 16).unwrap()));
    }

    fn composer_arithmetic(cs: &mut Composer<Fr>) {
        let x = cs.alloc(Fr::from(7));
        let y = cs.alloc(Fr::from(5));
        let z = cs.add(x, y);
        cs.enforce_constant(z, Fr::from(12));

        let u = cs.mul(x, y);
        cs.enforce_constant(u, Fr::from(35));

        let v = cs.sub(u, z);
        cs.enforce_constant(v, Fr::from(23));

        let one = cs.alloc(Fr::one());
        let zero = cs.alloc(Fr::zero());
        // 1*5*3 +2*1 -5 + 7 -19 = 0
        cs.poly_gate(
            vec![(one, Fr::from(2)), (y, -Fr::one()), (x, Fr::one())],
            Fr::from(3),
            -Fr::from(19),
        );

        cs.enforce_bool(one);
        cs.enforce_bool(zero);

        cs.enforce_eq(zero, Composer::<Fr>::null());

        let xx = cs.alloc(Fr::from(7));
        let x2 = cs.mul(x, xx);
        cs.enforce_constant(x2, Fr::from(49));
        cs.enforce_eq(x, xx);
    }

    fn composer_q0next(cs: &mut Composer<Fr>) {
        let x = cs.alloc(Fr::from(3));
        let x4x = cs.alloc(Fr::from(12));

        cs.poly_gate_with_next(
            vec![
                (x, Fr::one()),
                (x, Fr::one()),
                (x, Fr::one()),
                (x, Fr::one()),
            ],
            Fr::zero(),
            Fr::zero(),
            vec![(x4x, -Fr::one())],
        );
        cs.fully_customizable_poly_gates(
            vec![
                vec![
                    (x, Fr::one()),
                    (x, Fr::one()),
                    (x, Fr::one()),
                    (x, Fr::one()),
                ],
                vec![
                    (x4x, -Fr::one()),
                    (x, Fr::one()),
                    (x, Fr::one()),
                    (x, Fr::one()),
                ],
                vec![(x, Fr::one()), (x, -Fr::one())],
            ],
            vec![Fr::zero(), Fr::zero(), Fr::zero()],
            vec![Fr::zero(), Fr::zero(), Fr::zero()],
            vec![-Fr::one(), Fr::one(), Fr::zero()],
        );
    }

    fn composer_lookup(cs: &mut Composer<Fr>) {
        let table_index = cs.add_table(Table::xor_table(1));
        let xtt = cs.alloc(Fr::from(1));
        let ytt = cs.alloc(Fr::from(0));
        let ztt = cs.read_from_table(table_index, vec![xtt, ytt]).unwrap();
        cs.enforce_constant(ztt[0], Fr::from(1));

        let x = cs.alloc(Fr::from(3));
        let y = cs.mul(x, x);
        let z = cs.mul(x, y);
        let _u = cs.add(x, z);
        let _ = cs.read_from_table(table_index, vec![xtt, ytt]).unwrap();
        let _ = cs.read_from_table(table_index, vec![xtt, ytt]).unwrap();
    }

    fn composer_lookup2(cs: &mut Composer<Fr>) {
        let table_index = cs.add_table(Table::xor_table(3));
        let x = cs.alloc(Fr::from(1));
        let y = cs.alloc(Fr::from(2));
        let z = cs.alloc(Fr::from(5));
        let t = cs.read_from_table(table_index, vec![x, y]).unwrap();
        cs.enforce_constant(t[0], Fr::from(3));

        let t2 = cs.read_from_table(table_index, vec![y, x]).unwrap();
        cs.enforce_constant(t2[0], Fr::from(3));

        let t3 = cs.read_from_table(table_index, vec![t[0], x]).unwrap();
        cs.enforce_constant(t3[0], Fr::from(2));

        let t4 = cs.read_from_table(table_index, vec![z, y]).unwrap();
        cs.enforce_constant(t4[0], Fr::from(7));
    }

    fn composer_range(cs: &mut Composer<Fr>) {
        let u = cs.alloc(Fr::from(33));

        cs.enforce_range(u, 6).unwrap();

        let v = cs.alloc(Fr::from(65535));
        cs.enforce_range(v, 16).unwrap();

        // cs
    }

    fn composer_mimc(cs: &mut Composer<Fr>) {
        let x1 = cs.alloc(Fr::from(1));
        let x2 = cs.alloc(Fr::from(2));
        let x3 = cs.alloc(Fr::from(3));
        let x4 = cs.alloc(Fr::from(4));

        let hash = cs.MiMC_sponge(&[x1, x2], 1);
        let res1 = Fr::from(
            BigUint::parse_bytes(
                b"2BCEA035A1251603F1CEAF73CD4AE89427C47075BB8E3A944039FF1E3D6D2A6F",
                16,
            )
            .unwrap(),
        );
        assert_eq!(res1, cs.get_assignment(hash[0]));

        let hash1234 = cs.MiMC_sponge(&[x1, x2, x3, x4], 1);
        let res2 = Fr::from(
            BigUint::parse_bytes(
                b"03E86BDC4EAC70BD601473C53D8233B145FE8FD8BF6EF25F0B217A1DA305665C",
                16,
            )
            .unwrap(),
        );
        assert_eq!(res2, cs.get_assignment(hash1234[0]));

        // cs
    }

    // fn composer_substring(cs: &mut Composer<Fr>,) {
    //     // 608 bytes (4864 bits = 9*512 + 256)
    //     let sample_a = "66726f6d3a3d3f6762323331323f423f304c73677571504439773d3d3f3d203c6465657078686d406f75746c6f6f6b2e636f6d3e0d0a646174653a5475652c2032312044656320323032312031313a35363a3232202b303030300d0a7375626a6563743a55503078653633333139616239313563356539383638663133303761656463396131333733666561633465306261636633656333653161393961353134363834366537320d0a6d6573736167652d69643a3c535934503238324d42333734383043414546413237314643444337304532313632423537433940535934503238324d42333734382e415553503238322e50524f442e4f55544c4f4f4b2e434f4d3e0d0a636f6e74656e742d747970653a6d756c7469706172742f616c7465726e61746976653b20626f756e646172793d225f3030305f535934503238324d423337343830434145464132373146434443373045323136324235374339535934503238324d4233373438415553505f220d0a6d696d652d76657273696f6e3a312e300d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20633d72656c617865642f72656c617865643b20643d6f75746c6f6f6b2e636f6d3b20733d73656c6563746f72313b20683d46726f6d3a446174653a5375626a6563743a4d6573736167652d49443a436f6e74656e742d547970653a4d494d452d56657273696f6e3a582d4d532d45786368616e67652d53656e6465724144436865636b3b2062683d6530753870745966706b432b336334486d6845595358336b43306c6d386a753372436a387678475a776d413d3b20623d";
    //     let sample_a_bytes = hex::decode(sample_a).unwrap();
    //     // 19 bytes (152 bits) email address
    //     let sample_b_bytes = sample_a_bytes[32..=50].to_vec();

    //     // append 32bytes pepper
    //     let pepper = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
    //     let pepper_bytes = hex::decode(pepper).unwrap();
    //     let mut b_pepper_bytes = sample_b_bytes.clone();
    //     b_pepper_bytes.append(&mut pepper_bytes.clone());

    //     // "a" padding for sha256 (448-256=8*24, so add 1 '1', 191 '0', then add "bits of a" as u64)
    //     let mut sample_a_bytes_padding = sample_a_bytes.clone();
    //     sample_a_bytes_padding.push(1u8 << 7);
    //     for _ in 0..23 {
    //         sample_a_bytes_padding.push(0);
    //     }
    //     // "bits of a"
    //     let len = 4864u64.to_be_bytes();
    //     for e in len {
    //         sample_a_bytes_padding.push(e);
    //     }

    //     // "b" padding for sha256
    //     let mut b_pepper_bytes_padding = b_pepper_bytes.clone();
    //     b_pepper_bytes_padding.push(1u8 << 7);
    //     for _ in 0..4 {
    //         b_pepper_bytes_padding.push(0);
    //     }
    //     // "bits of b"
    //     let len = 408u64.to_be_bytes();
    //     for e in len {
    //         b_pepper_bytes_padding.push(e);
    //     }

    //     // here we only make the address private,
    //     let mut test_pub_match = sample_a_bytes_padding.clone();
    //     for i in 32..=50 {
    //         test_pub_match[i] = 0;
    //     }

    //     let mask = Fr::from(337845818);
    //     let mask_r = cs.alloc(mask);
    //     let l = cs.alloc(Fr::from(32));
    //     let m = cs.alloc(Fr::from(19));
    //     // alloc variables for "a"
    //     let mut a_vars = vec![];
    //     for e in &sample_a_bytes_padding {
    //         a_vars.push(cs.alloc(Fr::from(*e)));
    //     }
    //     let n = a_vars.len();
    //     // padding "a" to max_lens
    //     for _ in n..1024 {
    //         a_vars.push(cs.alloc(Fr::zero()));
    //     }
    //     // alloc variables for "b"
    //     let mut b_vars = vec![];
    //     for e in &b_pepper_bytes_padding {
    //         b_vars.push(cs.alloc(Fr::from(*e)));
    //     }
    //     let n = b_vars.len();
    //     // padding "b" to b_max_lens
    //     for _ in n..128 {
    //         b_vars.push(cs.alloc(Fr::zero()));
    //     }

    //     // pub match "a"
    //     // public string to be matched
    //     let mut email_header_pubmatch_vars = vec![];
    //     for e in &test_pub_match {
    //         email_header_pubmatch_vars.push(cs.alloc(Fr::from(*e)));
    //     }
    //     // padding to max_lens
    //     let n = email_header_pubmatch_vars.len();
    //     for _ in n..1024 {
    //         email_header_pubmatch_vars.push(cs.alloc(Fr::zero()));
    //     }

    //     // private substring check.
    //     let (_output_words_a, _output_words_b) = cs
    //     .add_substring_mask_poly_return_words(
    //         &a_vars,
    //         &b_vars,
    //         mask_r,
    //         l,
    //         m,
    //         1024,
    //         128,
    //     ).unwrap();

    //     cs.add_public_match_no_custom_gate(
    //         &a_vars,
    //         &email_header_pubmatch_vars,
    //         1024
    //     );

    //     // cs
    // }

    fn test_prove_verify(cs: &mut Composer<Fr>) -> Result<(), Error> {
        println!();
        let public_input = cs.compute_public_input();
        println!("cs.size() {}", cs.size());
        println!("cs.table_size() {}", cs.table_size());
        println!("cs.sorted_size() {}", cs.sorted_size());

        let rng = &mut test_rng();

        println!("time start:");
        let start = Instant::now();
        println!("compute_prover_key...");
        let pk = cs.compute_prover_key::<GeneralEvaluationDomain<Fr>>()?;
        println!("pk.domain_size() {}", pk.domain_size());
        println!("compute_prover_key...done");
        let pckey = PCKey::<ark_bn254::Bn254>::setup(pk.domain_size() + pk.program_width + 6, rng);
        println!("pckey.max_degree {}", pckey.max_degree);
        let mut prover =
            prover::Prover::<Fr, GeneralEvaluationDomain<Fr>, ark_bn254::Bn254>::new(pk);

        println!("init_comms...");
        let verifier_comms = prover.init_comms(&pckey);
        println!("init_comms...done");
        println!("time cost: {:?} ms", start.elapsed().as_millis()); // ms
        let mut verifier = Verifier::new(&prover, &public_input, &verifier_comms);

        println!("prove start:");
        let start = Instant::now();
        let proof = prover.prove(cs, &pckey, rng)?;
        println!("prove time cost: {:?} ms", start.elapsed().as_millis()); // ms

        let sha256_of_srs = pckey.sha256_of_srs();
        println!("verify start:");
        let start = Instant::now();
        let res = verifier.verify(&pckey.vk, &proof, &sha256_of_srs);
        println!("verify result: {}", res);
        assert!(res);
        println!("verify time cost: {:?} ms", start.elapsed().as_millis()); // ms

        Ok(())
    }

    #[test]
    fn test_lookup_size_no_padding() -> Result<(), Error> {
        let mut cs = Composer::new(4, true);

        composer_lookup(&mut cs);

        test_prove_verify(&mut cs)?;

        Ok(())
    }

    #[test]
    fn test_lookup_no_v() -> Result<(), Error> {
        let mut cs = Composer::new(4, true);

        let _table_index = cs.add_table(Table::xor_table(2));
        composer_basic(&mut cs);

        test_prove_verify(&mut cs)?;

        Ok(())
    }

    #[test]
    fn test_4column_enable_q0next() -> Result<(), Error> {
        let mut cs = Composer::new(4, true);
        // let _table_index = cs.add_table(Table::xor_table(2));

        composer_basic(&mut cs);
        composer_arithmetic(&mut cs);
        composer_q0next(&mut cs);
        composer_lookup2(&mut cs);
        composer_range(&mut cs);
        composer_mimc(&mut cs);
        // composer_substring(&mut cs);

        test_prove_verify(&mut cs)?;

        Ok(())
    }

    #[test]
    fn test_5column() -> Result<(), Error> {
        let mut cs = Composer::new(5, false);
        // let _table_index = cs.add_table(Table::xor_table(2));

        composer_basic(&mut cs);
        composer_arithmetic(&mut cs);
        // composer_q0next(&mut cs);
        composer_lookup2(&mut cs);
        composer_range(&mut cs);
        composer_mimc(&mut cs);
        // composer_substring(&mut cs);

        test_prove_verify(&mut cs)?;

        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_wrong_arith() {
        let mut cs = Composer::new(4, true);

        composer_lookup2(&mut cs);
        let x = cs.alloc(Fr::from(3));
        let y = cs.alloc(Fr::from(5));
        let z = cs.add(x, y);
        cs.enforce_constant(z, Fr::from(9));

        test_prove_verify(&mut cs).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_wrong_arith2() {
        let mut cs = Composer::new(4, true);

        let _table_index = cs.add_table(Table::xor_table(1));

        let x = cs.alloc(Fr::from(3));
        let y = cs.alloc(Fr::from(5));
        let z = cs.add(x, y);
        cs.poly_gate(
            vec![(z, -Fr::from(337845818)), (x, Fr::one()), (y, Fr::one())],
            Fr::from(337845818),
            -Fr::from(3),
        );

        test_prove_verify(&mut cs).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_wrong_arith3() {
        let mut cs = Composer::new(4, true);

        let _table_index = cs.add_table(Table::xor_table(1));

        let x = cs.alloc(Fr::from(3));
        let y = cs.alloc(Fr::from(5));
        cs.enforce_eq(x, y);

        test_prove_verify(&mut cs).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_wrong_lookup() {
        let mut cs = Composer::new(4, false);

        let table_index = cs.add_table(Table::xor_table(2));
        let x = cs.alloc(Fr::from(1));
        let z = cs.alloc(Fr::from(5));
        let t = cs.read_from_table(table_index, vec![x, z]).unwrap();
        cs.enforce_constant(t[0], Fr::from(4));

        test_prove_verify(&mut cs).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_wrong_range() {
        let mut cs = Composer::new(4, false);

        let _table_index = cs.add_table(Table::xor_table(1));

        let u = cs.alloc(Fr::from(33));
        cs.enforce_range(u, 7).unwrap();

        test_prove_verify(&mut cs).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_wrong_range2() {
        let mut cs = Composer::new(4, false);

        let _table_index = cs.add_table(Table::xor_table(1));

        let u = cs.alloc(Fr::from(16));
        cs.enforce_range(u, 4).unwrap();

        test_prove_verify(&mut cs).unwrap();
    }
}
