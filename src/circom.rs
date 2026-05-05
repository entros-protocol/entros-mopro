use crate::MoproError;
use circom_prover::{
    prover::{
        circom::{
            Proof as CircomProverProof, CURVE_BLS12_381, CURVE_BN254, G1 as CircomProverG1,
            G2 as CircomProverG2,
        },
        ProofLib as CircomProverProofLib,
    },
    CircomProver,
};
use num_bigint::BigUint;
use std::str::FromStr;

//
// Data structures for Circom proof representation. The String-based field
// types are required by UniFFI — its codegen does not understand BigUint —
// so the conversion to `circom-prover`'s native types is performed at the
// FFI boundary (see the TryFrom impls below).
//
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CircomProofResult {
    pub proof: CircomProof,
    pub inputs: Vec<String>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct G1 {
    pub x: String,
    pub y: String,
    pub z: String,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct G2 {
    pub x: Vec<String>,
    pub y: Vec<String>,
    pub z: Vec<String>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CircomProof {
    pub a: G1,
    pub b: G2,
    pub c: G1,
    pub protocol: String,
    pub curve: String,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ProofLib {
    #[default]
    Arkworks,
    Rapidsnark,
}

//
// Infallible conversions — `circom-prover` types into UniFFI types.
// BigUint → String never fails.
//
impl From<CircomProverProof> for CircomProof {
    fn from(proof: CircomProverProof) -> Self {
        CircomProof {
            a: proof.a.into(),
            b: proof.b.into(),
            c: proof.c.into(),
            protocol: proof.protocol,
            curve: proof.curve,
        }
    }
}

impl From<CircomProverG1> for G1 {
    fn from(g1: CircomProverG1) -> Self {
        G1 {
            x: g1.x.to_string(),
            y: g1.y.to_string(),
            z: g1.z.to_string(),
        }
    }
}

impl From<CircomProverG2> for G2 {
    fn from(g2: CircomProverG2) -> Self {
        G2 {
            x: vec![g2.x[0].to_string(), g2.x[1].to_string()],
            y: vec![g2.y[0].to_string(), g2.y[1].to_string()],
            z: vec![g2.z[0].to_string(), g2.z[1].to_string()],
        }
    }
}

impl From<ProofLib> for CircomProverProofLib {
    fn from(lib: ProofLib) -> Self {
        match lib {
            ProofLib::Arkworks => CircomProverProofLib::Arkworks,
            ProofLib::Rapidsnark => CircomProverProofLib::Rapidsnark,
        }
    }
}

//
// Fallible conversions — UniFFI types into `circom-prover` types. Each
// String field arrived from a non-Rust caller (JS, Kotlin, Swift) and may
// be malformed; `from_str` errors propagate as `MoproError::CircomError`
// rather than panicking the host process.
//
fn parse_bigint(s: &str, label: &str) -> Result<BigUint, MoproError> {
    BigUint::from_str(s)
        .map_err(|e| MoproError::CircomError(format!("invalid bigint at {label}: {e}")))
}

fn parse_g2_coord(coord: &[String], label: &str) -> Result<[BigUint; 2], MoproError> {
    if coord.len() != 2 {
        return Err(MoproError::CircomError(format!(
            "G2.{label} expected 2 elements, got {}",
            coord.len()
        )));
    }
    Ok([
        parse_bigint(&coord[0], &format!("G2.{label}[0]"))?,
        parse_bigint(&coord[1], &format!("G2.{label}[1]"))?,
    ])
}

impl TryFrom<G1> for CircomProverG1 {
    type Error = MoproError;
    fn try_from(g1: G1) -> Result<Self, Self::Error> {
        Ok(CircomProverG1 {
            x: parse_bigint(&g1.x, "G1.x")?,
            y: parse_bigint(&g1.y, "G1.y")?,
            z: parse_bigint(&g1.z, "G1.z")?,
        })
    }
}

impl TryFrom<G2> for CircomProverG2 {
    type Error = MoproError;
    fn try_from(g2: G2) -> Result<Self, Self::Error> {
        Ok(CircomProverG2 {
            x: parse_g2_coord(&g2.x, "x")?,
            y: parse_g2_coord(&g2.y, "y")?,
            z: parse_g2_coord(&g2.z, "z")?,
        })
    }
}

impl TryFrom<CircomProof> for CircomProverProof {
    type Error = MoproError;
    fn try_from(proof: CircomProof) -> Result<Self, Self::Error> {
        Ok(CircomProverProof {
            a: proof.a.try_into()?,
            b: proof.b.try_into()?,
            c: proof.c.try_into()?,
            protocol: proof.protocol,
            curve: proof.curve,
        })
    }
}

//
// Public FFI surface.
//

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_circom_proof(
    zkey_path: String,
    circuit_inputs: String,
    proof_lib: ProofLib,
) -> Result<CircomProofResult, MoproError> {
    let name = std::path::Path::new(zkey_path.as_str())
        .file_name()
        .ok_or_else(|| {
            MoproError::CircomError("failed to parse file name from zkey_path".to_string())
        })?;

    let witness_fn = crate::circom_get(name.to_str().unwrap_or("")).ok_or_else(|| {
        MoproError::CircomError(format!("Unknown ZKEY: {}", name.to_string_lossy()))
    })?;

    let ret = CircomProver::prove(proof_lib.into(), witness_fn, circuit_inputs, zkey_path)
        .map_err(|e| MoproError::CircomError(format!("Generate Proof error: {e}")))?;

    match ret.proof.curve.as_ref() {
        CURVE_BN254 | CURVE_BLS12_381 => Ok(CircomProofResult {
            proof: ret.proof.into(),
            inputs: ret.pub_inputs.into(),
        }),
        _ => Err(MoproError::CircomError(format!(
            "Unsupported curve: {}",
            ret.proof.curve
        ))),
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_circom_proof(
    zkey_path: String,
    proof_result: CircomProofResult,
    proof_lib: ProofLib,
) -> Result<bool, MoproError> {
    let prover_proof = circom_prover::prover::CircomProof {
        proof: proof_result.proof.try_into()?,
        pub_inputs: proof_result.inputs.into(),
    };
    CircomProver::verify(proof_lib.into(), prover_proof, zkey_path)
        .map_err(|e| MoproError::CircomError(format!("Verification error: {e}")))
}

#[macro_export]
macro_rules! set_circom_circuits {
    // Accept any number of (key, func) pairs.
    ($(($key:expr, $func:expr)),+ $(,)?) => {
        use circom_prover::witness::WitnessFn;

        const CIRCOM_CIRCUITS: &[(&'static str, WitnessFn)] = &[
            $(
                ($key, $func),
            )+
        ];

        #[inline]
        pub(crate) fn circom_get(name: &str) -> Option<WitnessFn> {
            CIRCOM_CIRCUITS
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| *v)
        }
    };
}
