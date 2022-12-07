use ark_std::{cfg_iter, cfg_iter_mut, cmp::max, format, vec, vec::Vec};
use ark_serialize::*;

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
pub struct Composer<F: Field> {
    // number of witness columns of the circuit
    pub program_width: usize,

    size: usize,
    is_finalized: bool,

    // witness
    wires: Map<String, Vec<Variable>>,
    selectors: Map<String, Vec<F>>,
    public_input: Vec<Variable>,

    // value in the Variable
    assignments: Vec<F>,
    // permutation info
    epicycles: Vec<Vec<Wire>>,
    tables: Vec<Table<F>>,

    // custom gates
    pub switches: ComposerConfig,
}

/// basics
impl<F: Field> Composer<F> {
    const SELECTOR_LABELS: [&'static str; 4] =
        ["q_m", "q_c", "q_lookup", "q_table"];

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
        let var = self.alloc_variable(value);

        var
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
        Variable(1)
    }

    /// any value should be OK
    pub fn any() -> Variable {
        Variable(0)
    }

    #[inline]
    fn alloc_variable(&mut self, value: F) -> Variable {
        let var = Variable(self.epicycles.len());
        //each variable have an epicycles (copy constraint)
        self.epicycles.push(Vec::new());
        self.assignments.push(value);

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
        println!("self.size() {}", self.size());
        println!("self.sorted_size() {}", self.sorted_size());

        let mut prover_key = ProverKey::new(
            size,
            self.input_size(),
            self.program_width,
            self.switches,
        )?;

        for (k, q) in self.selectors.iter() {
            prover_key.insert(&k, q.clone());
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

        for epicycle in self.epicycles.iter_mut() {
            *epicycle = cfg_iter_mut!(epicycle)
                //Move all wires down 'input size' lines
                .map(|w| Wire::new(w.col, w.row + input_size))
                .collect()
        }

        for (i, var) in self.public_input.iter().enumerate() {
            self.epicycles[var.0].push(Wire::new(0, i));
            for col in 1..self.program_width {
                // other witnesses just set 0 at PI' row
                self.epicycles[Self::null().0].push(Wire::new(col, i));
            }
        }

        let mut wires = Map::new();
        //put PI at the front of w_0, q0 must be 1 and other 'q' must be 0.
        for (label, wire) in self.wires.iter_mut() {
            let mut vars = if label == "w_0" {
                self.public_input.clone()
            } else {
                vec![Self::null(); input_size]
            };
            vars.append(wire);
            wires.insert(label.to_string(), vars);
        }
        self.wires = wires;

        let mut selectors = Map::new();
        for (label, selector) in self.selectors.iter_mut() {
            let mut values = if label == "q_0" {
                vec![F::one(); input_size]
            } else {
                vec![F::zero(); input_size]
            };
            values.append(selector);
            selectors.insert(label.to_string(), values);
        }
        self.selectors = selectors;

        self.is_finalized = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{kzg10::PCKey, verifier::Verifier, *};
    use ark_bn254::Fr;
    use ark_std::test_rng;
    use num_bigint::BigUint;

    #[test]
    fn composer_test_basic() -> Result<(), Error> {
        let mut cs = {
            // x^3 + x + pi = 35
            let mut cs = Composer::new(4, false);
            let pi = cs.alloc_input(Fr::from(5 as u64));
            let x = cs.alloc(Fr::from(3));
            let y = cs.mul(x, x);
            let z = cs.mul(x, y);
            let u = cs.add(x, z);
            let v = cs.add(pi, u);
            cs.enforce_constant(v, Fr::from(BigUint::parse_bytes(b"23", 16).unwrap()));

            let table_index = cs.add_table(Table::xor_table(2));
            let xtt = cs.alloc(Fr::from(1));
            let ytt = cs.alloc(Fr::from(2));
            let ztt = cs.read_from_table(table_index, vec![xtt, ytt])?;
            cs.enforce_constant(ztt[0], Fr::from(3));

            cs
        };
        let public_input = cs.compute_public_input();

        let rng = &mut test_rng();

        let pk = cs.compute_prover_key::<GeneralEvaluationDomain<Fr>>()?;
        let pckey = PCKey::<ark_bn254::Bn254>::setup(pk.domain_size() + pk.program_width + 6, rng);
        let mut prover =
            prover::Prover::<Fr, GeneralEvaluationDomain<Fr>, ark_bn254::Bn254>::new(pk);
        let verifier_comms = prover.init_comms(&pckey);
        println!("init_comms...done");

        let mut verifier = Verifier::new(&prover, &public_input, &verifier_comms);
        let proof = prover.prove(&mut cs, &pckey, rng)?;
        
        let sha256_of_srs = pckey.sha256_of_srs();
        verifier.verify(&pckey.vk, &proof, &sha256_of_srs);

        Ok(())
    }

    #[test]
    fn composer_test_lookup() -> Result<(), Error> {
        let mut cs = {
            let mut cs = Composer::new(4, false);

            let table_index = cs.add_table(Table::xor_table(1));
            let xtt = cs.alloc(Fr::from(1));
            let ytt = cs.alloc(Fr::from(0));
            let ztt = cs.read_from_table(table_index, vec![xtt, ytt])?;
            cs.enforce_constant(ztt[0], Fr::from(1));

            let x = cs.alloc(Fr::from(3));
            let y = cs.mul(x, x);
            let z = cs.mul(x, y);
            let _u = cs.add(x, z);
            let _ = cs.read_from_table(table_index, vec![xtt, ytt])?;
            let _ = cs.read_from_table(table_index, vec![xtt, ytt])?;

            cs
        };
        let public_input = cs.compute_public_input();

        let rng = &mut test_rng();

        let pk = cs.compute_prover_key::<GeneralEvaluationDomain<Fr>>()?;
        let pckey = PCKey::<ark_bn254::Bn254>::setup(pk.domain_size() + pk.program_width + 6, rng);
        let mut prover =
            prover::Prover::<Fr, GeneralEvaluationDomain<Fr>, ark_bn254::Bn254>::new(pk);
        let verifier_comms = prover.init_comms(&pckey);
        println!("init_comms...done");

        let mut verifier = Verifier::new(&prover, &public_input, &verifier_comms);
        let proof = prover.prove(&mut cs, &pckey, rng)?;
        
        let sha256_of_srs = pckey.sha256_of_srs();
        verifier.verify(&pckey.vk, &proof, &sha256_of_srs);

        Ok(())
    }

}
