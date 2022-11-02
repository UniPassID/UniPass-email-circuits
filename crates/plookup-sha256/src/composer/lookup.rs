use super::{Composer, Variable};
use crate::{Error, Field, Map};
use ark_std::{vec, vec::Vec};

#[derive(Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct Key<F: Field>(Vec<F>);

#[derive(Debug, Default)]
pub struct Table<F: Field> {
    pub id: String,
    //only set in circuit. start from 1.
    pub index: usize,
    pub size: usize,
    pub width: usize,
    pub key_width: usize,

    //the table. inner vec are columns
    pub columns: Vec<Vec<F>>,
    //lookup records. store index in this table
    pub lookups: Vec<usize>,

    // key may have multiple elements. value is index in this table
    pub key_map: Map<Vec<F>, usize>,
}

impl<F: Field> Table<F> {
    fn get_value_by_key(&mut self, key: &[F]) -> Result<Vec<F>, Error> {
        assert_eq!(key.len(), self.key_width);

        match self.key_map.get(key) {
            None => Err(Error::MissingLookupEntry),
            Some(&index) => {
                self.lookups.push(index);
                // value may have multiple elements.
                let values = (self.key_width..self.width)
                    .map(|i| self.columns[i][index])
                    .collect();
                Ok(values)
            }
        }
    }

    fn table_index(&self) -> usize {
        self.index
    }

    fn set_table_index(&mut self, index: usize) {
        self.index = index;
    }
}

impl<F: Field> Table<F> {
    /// create table contains all "a xor b = c". a and b are "bits" bits number.
    /// 3 colums, 2 are key, 1 is value. size of the table is "1 << bits * 2".
    pub fn xor_table(bits: usize) -> Self {
        let entries: u64 = 1 << bits;
        let size = 1 << bits * 2; //size is l*r
        let width = 3;
        let key_width = 2; //key is (l,r)
        let mut columns = vec![Vec::with_capacity(size); width];
        let mut key_map = Map::new();
        let mut row = 0;
        for l in 0..entries {
            for r in 0..entries {
                for (i, v) in vec![F::from(l), F::from(r), F::from(l ^ r)]
                    .into_iter()
                    .enumerate()
                {
                    columns[i].push(v);
                }

                key_map.insert(vec![F::from(l), F::from(r)], row);
                row += 1;
            }
        }

        Self {
            id: format!("xor_{}bits", bits),
            index: 0,
            size,
            width,
            key_width,
            columns,
            lookups: Vec::new(),

            key_map,
        }
    }
}

impl<F: Field> Composer<F> {
    //add all tables into a 'single big table'. will use an extra column, distinguish different tables
    pub(super) fn compute_table_values(&self) -> Vec<Vec<F>> {
        // one column
        let mut table_values = vec![Vec::with_capacity(self.table_size()); self.program_width + 1];
        for (i, table) in self.tables.iter().enumerate() {
            for col in 0..table.width {
                table_values[col].extend(table.columns[col].iter());
            }
            for col in table.width..(self.program_width) {
                table_values[col].extend(vec![F::zero(); table.size]);
            }
            //i is the index of different tables.
            table_values[self.program_width].extend(vec![F::from((i + 1) as u64); table.size])
        }

        table_values
    }

    pub(super) fn compute_sorted_values(&self) -> Vec<Vec<F>> {
        let mut sorted_values =
            vec![Vec::with_capacity(self.sorted_size()); self.program_width + 1];

        for (i, table) in self.tables.iter().enumerate() {
            // S. add table T. store index.
            let mut lookups: Vec<_> = (0..table.size).collect();
            // add V
            lookups.extend(&table.lookups);
            // S must ordered
            lookups.sort();

            for col in 0..table.width {
                sorted_values[col].extend(lookups.iter().map(|&i| table.columns[col][i]));
            }
            //padding
            for col in table.width..self.program_width {
                sorted_values[col].extend(vec![F::zero(); lookups.len()]);
            }
            // extra column, distinguish different tables
            sorted_values[self.program_width].extend(vec![F::from((i + 1) as u64); lookups.len()])
        }

        sorted_values
    }

    pub(super) fn table_size(&self) -> usize {
        let mut size = 0;
        for table in self.tables.iter() {
            size += table.size;
        }

        size
    }

    pub(super) fn sorted_size(&self) -> usize {
        let mut size = 0;
        for table in self.tables.iter() {
            size += table.size + table.lookups.len();
        }

        size
    }
}

impl<F: Field> Composer<F> {
    /// add a new table into the circuit.
    /// table index starts at 1.
    /// return index of the table.
    pub fn add_table(&mut self, mut table: Table<F>) -> usize {
        if !self.enable_lookup {
            self.enable_lookup = true;
        }
        let result = self.get_table_index(table.id.clone());
        if result != 0 {
            // println!("table id already exists");
            return result;
        }

        let index = self.tables.len() + 1;
        table.set_table_index(index);

        self.tables.push(table);

        index
    }

    /// if id not exist, return 0
    pub fn get_table_index(&self, table_id: String) -> usize {
        for table in &self.tables {
            if table.id == table_id {
                return table.index;
            }
        }

        return 0;
    }

    pub fn get_table(&self, index: usize) -> Result<&Table<F>, Error> {
        if (index == 0) || (index - 1 >= self.tables.len()) {
            return Err(Error::NoSuchTable);
        }

        Ok(&self.tables[index - 1])
    }

    pub fn get_table_mut(&mut self, index: usize) -> Result<&mut Table<F>, Error> {
        if (index == 0) || (index - 1 >= self.tables.len()) {
            return Err(Error::NoSuchTable);
        }

        Ok(&mut self.tables[index - 1])
    }

    /// like "map", use key to "lookup" the value.
    /// will add a line as lookup.
    /// return the value vars
    pub fn read_from_table(
        &mut self,
        table_index: usize,
        key: Vec<Variable>,
    ) -> Result<Vec<Variable>, Error> {
        assert!(!self.is_finalized);

        let lookup_key = self.get_assignments(&key);
        let lookup_value = self
            .get_table_mut(table_index)?
            .get_value_by_key(&lookup_key)?;
        //alloc variable for lookup result
        let value: Vec<_> = lookup_value.into_iter().map(|v| self.alloc(v)).collect();

        let wires = key.into_iter().chain(value.clone()).collect();
        // write this lookup into witness
        let index = self.insert_gate(wires);

        self.selectors.get_mut("q_lookup").unwrap()[index] = F::one();
        // extra column, distinguish different tables. start from 1.
        self.selectors.get_mut("q_table").unwrap()[index] = F::from(table_index as u64);

        Ok(value)
    }
}
