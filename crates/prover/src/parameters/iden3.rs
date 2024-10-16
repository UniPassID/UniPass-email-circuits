use std::{
    collections::HashMap,
    io::{Read, Result as IoResult, Seek, SeekFrom},
};

use plonk::{
    ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine},
    ark_ec::{AffineCurve, PairingEngine},
    ark_ff::{BigInteger256, FromBytes},
    ark_serialize::{CanonicalDeserialize, SerializationError},
    ark_std::{log2, Zero},
    kzg10::PCKey,
    Field,
};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Section {
    position: u64,
    #[allow(dead_code)]
    size: usize,
}

pub struct PtauHeader {
    pub n8: u32,
    pub q: BigInteger256,
    pub power: u32,
    pub ceremony_power: u32,
}

pub struct Ptau {
    pub ptau_header: PtauHeader,
    pub groth_header: HeaderGroth,
    pub tau_g1: Vec<G1Affine>,
    pub tau_g2: Vec<G2Affine>,
    pub alpha_tau_g1: Vec<G1Affine>,
    pub beta_tau_g1: Vec<G1Affine>,
    pub beta_g2: G2Affine,
}

#[derive(Debug, Serialize)]
pub struct BinFile<'a, R> {
    #[allow(dead_code)]
    ftype: String,
    #[allow(dead_code)]
    version: u32,
    sections: HashMap<u32, Vec<Section>>,
    #[serde(skip)]
    reader: &'a mut R,
}

impl<'a, R: Read + Seek> BinFile<'a, R> {
    pub fn new(reader: &'a mut R) -> IoResult<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        let mut u32_buf = [0u8; 4];
        let mut u64_buf = [0u8; 8];

        reader.read_exact(&mut u32_buf)?;
        let version = u32::from_le_bytes(u32_buf);

        reader.read_exact(&mut u32_buf)?;
        let num_sections = u32::from_le_bytes(u32_buf);

        let mut sections = HashMap::new();
        for _ in 0..num_sections {
            reader.read_exact(&mut u32_buf)?;
            let section_id = u32::from_le_bytes(u32_buf);
            reader.read_exact(&mut u64_buf)?;
            let section_length = u64::from_le_bytes(u64_buf);

            let section = sections.entry(section_id).or_insert_with(Vec::new);
            section.push(Section {
                position: reader.stream_position()?,
                size: section_length as usize,
            });

            reader.seek(SeekFrom::Current(section_length as i64))?;
        }

        Ok(Self {
            ftype: std::str::from_utf8(&magic[..]).unwrap().to_string(),
            version,
            sections,
            reader,
        })
    }

    pub fn ptau_header(&mut self) -> IoResult<PtauHeader> {
        let section = self.get_section(1);
        self.reader.seek(SeekFrom::Start(section.position))?;
        let n8q: u32 = FromBytes::read(&mut self.reader)?;
        // group order r of Bn254
        let q = BigInteger256::read(&mut self.reader)?;
        let power: u32 = FromBytes::read(&mut self.reader)?;
        let ceremony_power: u32 = FromBytes::read(&mut self.reader)?;

        Ok(PtauHeader {
            n8: n8q,
            q,
            power,
            ceremony_power,
        })
    }

    pub fn ptau(&mut self) -> IoResult<Ptau> {
        let ptau_header = self.ptau_header()?;
        let groth_header = self.groth_header()?;
        let tau_g1 = self.g1_section((2u32.pow(ptau_header.power) * 2 - 1) as usize, 2)?;
        let tau_g2 = self.g2_section((2u32.pow(ptau_header.power)) as usize, 3)?;
        let alpha_tau_g1 = self.g1_section((2u32.pow(ptau_header.power)) as usize, 4)?;
        let beta_tau_g1 = self.g1_section((2u32.pow(ptau_header.power)) as usize, 5)?;
        let beta_g2 = self.g2_section(1, 6)?;

        Ok(Ptau {
            ptau_header,
            groth_header,
            tau_g1,
            tau_g2,
            alpha_tau_g1,
            beta_tau_g1,
            beta_g2: beta_g2[0],
        })
    }

    pub fn pckey(&mut self) -> IoResult<PCKey<Bn254>> {
        let ptau_header = self.ptau_header()?;
        println!(
            "power: {}, ceremony_power: {}",
            ptau_header.power, ptau_header.ceremony_power
        );
        let tau_g1 = self.g1_section((2u32.pow(ptau_header.power) * 2 - 1) as usize, 2)?;
        let tau_g2 = self.g2_section((2u32.pow(ptau_header.power)) as usize, 3)?;
        let max_degree = tau_g1.len() - 1;

        Ok(PCKey {
            powers: tau_g1,
            max_degree,
            vk: plonk::kzg10::VKey {
                g: <Bn254 as PairingEngine>::G1Affine::prime_subgroup_generator(),
                h: <Bn254 as PairingEngine>::G2Affine::prime_subgroup_generator(),
                beta_h: tau_g2[1],
                max_degree,
            },
        })
    }

    pub fn get_section(&self, id: u32) -> Section {
        self.sections.get(&id).unwrap()[0].clone()
    }

    pub fn groth_header(&mut self) -> IoResult<HeaderGroth> {
        let section = self.get_section(2);
        let header = HeaderGroth::new(&mut self.reader, &section)?;
        Ok(header)
    }

    pub fn ic(&mut self, n_public: usize) -> IoResult<Vec<G1Affine>> {
        // the range is non-inclusive so we do +1 to get all inputs
        self.g1_section(n_public + 1, 3)
    }

    pub fn a_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 5)
    }

    pub fn b_g1_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 6)
    }

    pub fn b_g2_query(&mut self, n_vars: usize) -> IoResult<Vec<G2Affine>> {
        self.g2_section(n_vars, 7)
    }

    pub fn l_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 8)
    }

    pub fn h_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 9)
    }

    pub fn g1_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G1Affine>> {
        let section = self.get_section(section_id as u32);
        self.reader.seek(SeekFrom::Start(section.position))?;
        deserialize_g1_vec(self.reader, num as u32)
    }

    pub fn g2_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G2Affine>> {
        let section = self.get_section(section_id as u32);
        self.reader.seek(SeekFrom::Start(section.position))?;
        deserialize_g2_vec(self.reader, num as u32)
    }
}

#[derive(Default, Clone, Debug, CanonicalDeserialize)]
pub struct ZVerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g1: G1Affine,
    pub delta_g2: G2Affine,
}

impl ZVerifyingKey {
    fn new<R: Read>(reader: &mut R) -> IoResult<Self> {
        let alpha_g1 = deserialize_g1(reader)?;
        let beta_g1 = deserialize_g1(reader)?;
        let beta_g2 = deserialize_g2(reader)?;
        let gamma_g2 = deserialize_g2(reader)?;
        let delta_g1 = deserialize_g1(reader)?;
        let delta_g2 = deserialize_g2(reader)?;

        Ok(Self {
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g1,
            delta_g2,
        })
    }
}

#[derive(Clone, Debug)]
pub struct HeaderGroth {
    #[allow(dead_code)]
    pub n8q: u32,
    #[allow(dead_code)]
    pub q: BigInteger256,
    #[allow(dead_code)]
    pub n8r: u32,
    #[allow(dead_code)]
    pub r: BigInteger256,

    pub n_vars: usize,
    pub n_public: usize,

    pub domain_size: u32,
    #[allow(dead_code)]
    pub power: u32,

    pub verifying_key: ZVerifyingKey,
}

impl HeaderGroth {
    fn new<R: Read + Seek>(reader: &mut R, section: &Section) -> IoResult<Self> {
        reader.seek(SeekFrom::Start(section.position))?;
        Self::read(reader)
    }

    fn read<R: Read>(mut reader: &mut R) -> IoResult<Self> {
        // TODO: Impl From<u32> in Arkworks
        let n8q: u32 = FromBytes::read(&mut reader)?;
        // group order r of Bn254
        let q = BigInteger256::read(&mut reader)?;

        let n8r: u32 = FromBytes::read(&mut reader)?;
        // Prime field modulus
        let r = BigInteger256::read(&mut reader)?;

        let n_vars = u32::read(&mut reader)? as usize;
        let n_public = u32::read(&mut reader)? as usize;

        let domain_size: u32 = FromBytes::read(&mut reader)?;
        let power = log2(domain_size as usize);

        let verifying_key = ZVerifyingKey::new(&mut reader)?;

        Ok(Self {
            n8q,
            q,
            n8r,
            r,
            n_vars,
            n_public,
            domain_size,
            power,
            verifying_key,
        })
    }
}

// need to divide by R, since snarkjs outputs the zkey with coefficients
// multiplieid by R^2
#[allow(dead_code)]
fn deserialize_field_fr<R: Read>(reader: &mut R) -> IoResult<Fr> {
    let bigint = BigInteger256::read(reader)?;
    Ok(Fr::new(Fr::new(bigint).into_repr()))
}

// skips the multiplication by R because Circom points are already in Montgomery form
fn deserialize_field<R: Read>(reader: &mut R) -> IoResult<Fq> {
    let bigint = BigInteger256::read(reader)?;
    // if you use ark_ff::PrimeField::from_repr it multiplies by R
    Ok(Fq::new(bigint))
}

pub fn deserialize_field2<R: Read>(reader: &mut R) -> IoResult<Fq2> {
    let c0 = deserialize_field(reader)?;
    let c1 = deserialize_field(reader)?;
    Ok(Fq2::new(c0, c1))
}

fn deserialize_g1<R: Read>(reader: &mut R) -> IoResult<G1Affine> {
    let x = deserialize_field(reader)?;
    let y = deserialize_field(reader)?;
    let infinity = x.is_zero() && y.is_zero();
    Ok(G1Affine::new(x, y, infinity))
}

fn deserialize_g2<R: Read>(reader: &mut R) -> IoResult<G2Affine> {
    let f1 = deserialize_field2(reader)?;
    let f2 = deserialize_field2(reader)?;
    let infinity = f1.is_zero() && f2.is_zero();
    Ok(G2Affine::new(f1, f2, infinity))
}

fn deserialize_g1_vec<R: Read>(reader: &mut R, n_vars: u32) -> IoResult<Vec<G1Affine>> {
    (0..n_vars).map(|_| deserialize_g1(reader)).collect()
}

fn deserialize_g2_vec<R: Read>(reader: &mut R, n_vars: u32) -> IoResult<Vec<G2Affine>> {
    (0..n_vars).map(|_| deserialize_g2(reader)).collect()
}
