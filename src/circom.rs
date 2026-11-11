use crate::MoproError;
use circom_prover::{
    prover::{
        circom::{
            Proof as CircomProverProof, CURVE_BN254, G1 as CircomProverG1, G2 as CircomProverG2,
            PROTOCOL_GROTH16,
        },
        ProofLib as CircomProverProofLib,
    },
    CircomProver,
};
use num_bigint::BigUint;
use std::str::FromStr;

fn check_key_identity(zkey_path: &str) -> Result<(), MoproError> {
    use sha2::{Digest, Sha256};
    let filename = std::path::Path::new(zkey_path)
        .file_name()
        .and_then(|name| name.to_str());
    let expected = match filename {
        Some("entros_hamming_final.zkey") => env!("ENTROS_LEGACY_ZKEY_SHA256"),
        #[cfg(feature = "request-bound-v1")]
        Some("entros_request_bound_v1_final.zkey") => env!("ENTROS_BOUND_ZKEY_SHA256"),
        _ => {
            return Err(MoproError::CircomError(
                "Unknown proving artifact".to_owned(),
            ))
        }
    };
    let bytes = std::fs::read(zkey_path)
        .map_err(|error| MoproError::CircomError(format!("Read proving key: {error}")))?;
    if format!("{:x}", Sha256::digest(bytes)) != expected {
        return Err(MoproError::CircomError(
            "Proving key SHA-256 mismatch".to_owned(),
        ));
    }
    Ok(())
}

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
    if s.is_empty()
        || s.len() > 78
        || !s.bytes().all(|byte| byte.is_ascii_digit())
        || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(MoproError::CircomError(format!(
            "Noncanonical coordinate at {label}"
        )));
    }
    let value = BigUint::from_str(s)
        .map_err(|e| MoproError::CircomError(format!("Invalid coordinate at {label}: {e}")))?;
    let modulus = BigUint::from_str(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    )
    .map_err(|e| MoproError::CircomError(format!("Invalid base field modulus: {e}")))?;
    if value >= modulus {
        return Err(MoproError::CircomError(format!(
            "Coordinate outside the base field at {label}"
        )));
    }
    Ok(value)
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
        let point = CircomProverG1 {
            x: parse_bigint(&g1.x, "G1.x")?,
            y: parse_bigint(&g1.y, "G1.y")?,
            z: parse_bigint(&g1.z, "G1.z")?,
        };
        let zero = BigUint::from(0u8);
        let infinity = point.x == zero && point.y == zero;
        if point.z != BigUint::from(u8::from(!infinity)) {
            return Err(MoproError::CircomError(
                "Expected an affine G1 point".to_owned(),
            ));
        }
        let affine = if infinity {
            ark_bn254::G1Affine::identity()
        } else {
            ark_bn254::G1Affine::new_unchecked(point.x.clone().into(), point.y.clone().into())
        };
        if !affine.is_on_curve() || !affine.is_in_correct_subgroup_assuming_on_curve() {
            return Err(MoproError::CircomError("Invalid G1 curve point".to_owned()));
        }
        Ok(point)
    }
}

impl TryFrom<G2> for CircomProverG2 {
    type Error = MoproError;
    fn try_from(g2: G2) -> Result<Self, Self::Error> {
        let point = CircomProverG2 {
            x: parse_g2_coord(&g2.x, "x")?,
            y: parse_g2_coord(&g2.y, "y")?,
            z: parse_g2_coord(&g2.z, "z")?,
        };
        let zero = BigUint::from(0u8);
        let infinity = point
            .x
            .iter()
            .chain(point.y.iter())
            .all(|value| value == &zero);
        if point.z != [BigUint::from(u8::from(!infinity)), zero] {
            return Err(MoproError::CircomError(
                "Expected an affine G2 point".to_owned(),
            ));
        }
        let affine = if infinity {
            ark_bn254::G2Affine::identity()
        } else {
            ark_bn254::G2Affine::new_unchecked(
                ark_bn254::Fq2::new(point.x[0].clone().into(), point.x[1].clone().into()),
                ark_bn254::Fq2::new(point.y[0].clone().into(), point.y[1].clone().into()),
            )
        };
        if !affine.is_on_curve() || !affine.is_in_correct_subgroup_assuming_on_curve() {
            return Err(MoproError::CircomError("Invalid G2 curve point".to_owned()));
        }
        Ok(point)
    }
}

impl TryFrom<CircomProof> for CircomProverProof {
    type Error = MoproError;
    fn try_from(proof: CircomProof) -> Result<Self, Self::Error> {
        if proof.protocol != PROTOCOL_GROTH16 || proof.curve != CURVE_BN254 {
            return Err(MoproError::CircomError(
                "Expected a BN254 Groth16 proof".to_owned(),
            ));
        }
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
    check_key_identity(&zkey_path)?;
    let name = std::path::Path::new(zkey_path.as_str())
        .file_name()
        .ok_or_else(|| {
            MoproError::CircomError("failed to parse file name from zkey_path".to_string())
        })?;

    let witness_fn = crate::circom_get(name.to_str().unwrap_or("")).ok_or_else(|| {
        MoproError::CircomError(format!("Unknown ZKEY: {}", name.to_string_lossy()))
    })?;

    let circuit_inputs = crate::inputs::normalize(
        &circuit_inputs,
        name == "entros_request_bound_v1_final.zkey",
    )?;

    let ret = CircomProver::prove(
        proof_lib.clone().into(),
        witness_fn,
        circuit_inputs,
        zkey_path.clone(),
    )
    .map_err(|e| MoproError::CircomError(format!("Generate Proof error: {e}")))?;

    let result = match ret.proof.curve.as_ref() {
        CURVE_BN254 => Ok(CircomProofResult {
            proof: ret.proof.into(),
            inputs: ret.pub_inputs.into(),
        }),
        _ => Err(MoproError::CircomError(format!(
            "Unsupported curve: {}",
            ret.proof.curve
        ))),
    }?;
    // The native witness adapter does not enforce circuit assertions.
    if !verify_circom_proof(zkey_path, result.clone(), proof_lib)? {
        return Err(MoproError::CircomError(
            "Generated proof does not satisfy the circuit".to_owned(),
        ));
    }
    Ok(result)
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_circom_proof(
    zkey_path: String,
    proof_result: CircomProofResult,
    proof_lib: ProofLib,
) -> Result<bool, MoproError> {
    check_key_identity(&zkey_path)?;
    let bound = std::path::Path::new(&zkey_path)
        .file_name()
        .is_some_and(|name| name == "entros_request_bound_v1_final.zkey");
    crate::inputs::validate_public_inputs(&proof_result.inputs, bound)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_noncanonical_curve_coordinates() {
        for value in [
            "",
            "-1",
            "+1",
            "01",
            " 1",
            "1 ",
            "1.0",
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
        ] {
            assert!(parse_bigint(value, "test").is_err(), "{value}");
        }
        assert!(parse_bigint(&"9".repeat(10000), "test").is_err());
    }

    #[test]
    fn validates_curve_points_before_dependency_conversion() {
        assert!(CircomProverG1::try_from(G1 {
            x: "1".into(),
            y: "2".into(),
            z: "1".into()
        })
        .is_ok());
        for (x, y, z) in [("1", "1", "1"), ("1", "2", "2"), ("0", "0", "1")] {
            assert!(CircomProverG1::try_from(G1 {
                x: x.into(),
                y: y.into(),
                z: z.into()
            })
            .is_err());
        }
        assert!(CircomProverG1::try_from(G1 {
            x: "0".into(),
            y: "0".into(),
            z: "0".into()
        })
        .is_ok());
        assert!(CircomProverG2::try_from(G2 {
            x: vec!["1".into(), "1".into()],
            y: vec!["1".into(), "1".into()],
            z: vec!["1".into(), "0".into()],
        })
        .is_err());
    }
}
