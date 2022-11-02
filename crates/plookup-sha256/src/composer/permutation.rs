use super::{Composer, Domain, Wire};
use crate::{coset_generator, Field};
use ark_std::vec::Vec;

impl<F: Field> Composer<F> {
    pub(super) fn compute_sigmas(&self, domain: impl Domain<F>) -> Vec<Vec<F>> {
        let length = domain.size();
        let sigmas = {
            let mut sigmas: Vec<Vec<Wire>> = Vec::with_capacity(self.program_width);
            for col in 0..self.program_width {
                //store original Wire
                sigmas.push((0..length).map(|row| Wire::new(col, row)).collect())
            }

            //'wires' are the copy constraint of a variable
            for wires in self.epicycles.iter() {
                if wires.len() <= 1 {
                    continue;
                }
                //get 'next' wire
                for (curr, curr_wire) in wires.iter().enumerate() {
                    let next = match curr {
                        0 => wires.len() - 1,
                        _ => curr - 1,
                    };
                    let next_wire = &wires[next];
                    sigmas[curr_wire.col][curr_wire.row] = *next_wire;
                }
            }

            sigmas
        };

        let roots: Vec<_> = domain.elements().collect();
        let mut sigma_values = Vec::with_capacity(self.program_width);
        for sigma in sigmas {
            sigma_values.push(
                sigma
                    .iter()
                    .map(|w| roots[w.row] * coset_generator::<F>(w.col))
                    .collect(),
            );
        }
        sigma_values
    }
}
