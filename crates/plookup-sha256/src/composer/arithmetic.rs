use super::{Composer, Variable};
use crate::Field;
use ark_std::{format, vec, vec::Vec};

/// arithmetic gates
impl<F: Field> Composer<F> {
    /// o = l + r
    pub fn add(&mut self, var_l: Variable, var_r: Variable) -> Variable {
        let var_o = self.alloc_variable(self.assignments[var_l.0] + self.assignments[var_r.0]);
        self.add_gate(var_l, var_r, var_o);

        var_o
    }

    /// o = l + r
    pub fn add_gate(&mut self, var_l: Variable, var_r: Variable, var_o: Variable) {
        self.poly_gate(
            vec![(var_l, F::one()), (var_r, F::one()), (var_o, -F::one())],
            F::zero(),
            F::zero(),
        )
    }

    /// o = l * r
    pub fn mul(&mut self, var_l: Variable, var_r: Variable) -> Variable {
        let var_o = self.alloc_variable(self.assignments[var_l.0] * self.assignments[var_r.0]);
        self.mul_gate(var_l, var_r, var_o);

        var_o
    }

    /// o = l * r
    pub fn mul_gate(&mut self, var_l: Variable, var_r: Variable, var_o: Variable) {
        self.poly_gate(
            vec![(var_l, F::zero()), (var_r, F::zero()), (var_o, -F::one())],
            F::one(),
            F::zero(),
        )
    }

    /// var === value
    pub fn enforce_constant(&mut self, var: Variable, value: F) {
        self.poly_gate(vec![(var, F::one())], F::zero(), -value);
    }

    /// q_arith * (q_0 * w_0 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 +... + q_m * w_0 * w_1 + q_c) = 0
    pub fn poly_gate(&mut self, wires: Vec<(Variable, F)>, mul_scaling: F, const_scaling: F) {
        assert!(!self.is_finalized);
        assert!(wires.len() <= self.program_width);

        let index = self.insert_gate(wires.iter().map(|(v, _)| *v).collect());
        for i in 0..wires.len() {
            self.selectors.get_mut(&format!("q_{}", i)).unwrap()[index] = wires[i].1;
        }
        self.selectors.get_mut("q_m").unwrap()[index] = mul_scaling;
        self.selectors.get_mut("q_c").unwrap()[index] = const_scaling;
        self.selectors.get_mut("q_arith").unwrap()[index] = F::one();
    }

    /// q_arith * (q_0 * w_0 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 +... + q_m * w_0 * w_1 + q_c + q0next * w0next) = 0.
    /// next_wire only accept one tuple as w0next. the other will be ignored
    pub fn poly_gate_with_next(
        &mut self,
        wires: Vec<(Variable, F)>,
        mul_scaling: F,
        const_scaling: F,
        next_wire: Vec<(Variable, F)>,
    ) {
        assert!(!self.is_finalized);
        assert!(wires.len() <= self.program_width);

        let index = self.insert_gate(wires.iter().map(|(v, _)| *v).collect());
        for i in 0..wires.len() {
            self.selectors.get_mut(&format!("q_{}", i)).unwrap()[index] = wires[i].1;
        }
        self.selectors.get_mut("q_m").unwrap()[index] = mul_scaling;
        self.selectors.get_mut("q_c").unwrap()[index] = const_scaling;
        self.selectors.get_mut("q_arith").unwrap()[index] = F::one();

        if next_wire.len() != 0 {
            let nextindex = self.insert_gate(vec![next_wire[0].0]);
            assert_eq!(nextindex, index + 1);
            self.selectors.get_mut(&format!("q0next")).unwrap()[index] = next_wire[0].1;
        }
    }

    /// multiple: q_arith * (q_0 * w_0 + q_1 * w_1 + q_2 * w_2 + q_3 * w_3 +... + q_m * w_0 * w_1 + q_c + q0next * w0next) = 0.
    /// will create multiple poly gates adjacently. make better use of 'next'
    pub fn fully_costomizable_poly_gates(
        &mut self,
        multiple_wires: Vec<Vec<(Variable, F)>>,
        q_arith: Vec<F>,
        q_m: Vec<F>,
        q_c: Vec<F>,
        q0next: Vec<F>,
    ) {
        assert!(!self.is_finalized);
        let n = multiple_wires.len();
        assert_eq!(n, q_arith.len());
        assert_eq!(n, q_m.len());
        assert_eq!(n, q_c.len());
        assert_eq!(n, q0next.len());
        for wires in &multiple_wires {
            assert!(wires.len() <= self.program_width);
        }

        let mut current_index = self.size();
        for i in 0..n {
            let index = self.insert_gate(multiple_wires[i].iter().map(|(v, _)| *v).collect());
            assert_eq!(current_index, index);

            for j in 0..multiple_wires[i].len() {
                self.selectors.get_mut(&format!("q_{}", j)).unwrap()[index] =
                    multiple_wires[i][j].1;
            }
            self.selectors.get_mut("q_m").unwrap()[index] = q_m[i];
            self.selectors.get_mut("q_c").unwrap()[index] = q_c[i];
            self.selectors.get_mut("q_arith").unwrap()[index] = q_arith[i];
            self.selectors.get_mut("q0next").unwrap()[index] = q0next[i];

            current_index += 1;
        }
    }

    /// var = 0 or 1
    pub fn enforce_bool(&mut self, var: Variable) {
        self.poly_gate(
            vec![(var, -F::one()), (var, F::zero())],
            F::one(),
            F::zero(),
        );
    }

    /// var0 == var1 (todo: use permutation)
    pub fn enforce_eq(&mut self, var_0: Variable, var_1: Variable) {
        self.poly_gate(
            vec![(var_0, -F::one()), (var_1, F::one())],
            F::zero(),
            F::zero(),
        );
    }
}
