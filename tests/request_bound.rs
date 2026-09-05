#![cfg(feature = "request-bound-v1")]

use entros_mopro::{
    generate_circom_proof, verify_circom_proof, CircomProof, CircomProofResult, ProofLib, G1, G2,
};
use serde::Deserialize;
use std::{error::Error, fs::OpenOptions, io::Write, path::PathBuf};

#[derive(Deserialize)]
struct Proof {
    pi_a: [String; 3],
    pi_b: [[String; 2]; 3],
    pi_c: [String; 3],
    protocol: String,
    curve: String,
}

#[derive(Deserialize)]
struct Fixture {
    input: serde_json::Value,
    proof: Proof,
    public_signals_decimal: Vec<String>,
}

fn g1([x, y, z]: [String; 3]) -> G1 {
    G1 { x, y, z }
}

#[test]
fn native_and_javascript_proofs_share_the_bound_statement() -> Result<(), Box<dyn Error>> {
    let key = std::env::var("ENTROS_BOUND_ZKEY_PATH")?;
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(std::env::var(
        "ENTROS_BOUND_PROOF_FIXTURE",
    )?)?)?;
    let result = generate_circom_proof(key.clone(), fixture.input.to_string(), ProofLib::Arkworks)?;
    assert_eq!(result.inputs.len(), 6);
    assert_eq!(result.inputs, fixture.public_signals_decimal);
    assert!(verify_circom_proof(
        key.clone(),
        result.clone(),
        ProofLib::Arkworks
    )?);

    let [x, y, z] = fixture.proof.pi_b;
    let javascript = CircomProofResult {
        inputs: fixture.public_signals_decimal,
        proof: CircomProof {
            a: g1(fixture.proof.pi_a),
            b: G2 {
                x: x.to_vec(),
                y: y.to_vec(),
                z: z.to_vec(),
            },
            c: g1(fixture.proof.pi_c),
            protocol: fixture.proof.protocol,
            curve: fixture.proof.curve,
        },
    };
    assert!(verify_circom_proof(
        key.clone(),
        javascript,
        ProofLib::Arkworks
    )?);
    for index in 0..6 {
        let mut changed = result.clone();
        let value: num_bigint::BigUint = changed.inputs[index].parse()?;
        changed.inputs[index] = (value + num_bigint::BigUint::from(1u8)).to_string();
        assert!(!verify_circom_proof(
            key.clone(),
            changed,
            ProofLib::Arkworks
        )?);
    }
    let modulus: num_bigint::BigUint =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617".parse()?;
    for index in 0..6 {
        let mut aliased = result.clone();
        let value: num_bigint::BigUint = aliased.inputs[index].parse()?;
        aliased.inputs[index] = (value + &modulus).to_string();
        assert!(matches!(
            verify_circom_proof(key.clone(), aliased, ProofLib::Arkworks),
            Ok(false) | Err(_)
        ));
    }
    let output = serde_json::json!({
        "syntheticOnly": true,
        "schema": "request-bound-v1",
        "nativeWitness": true,
        "publicSignals": result.inputs,
        "proof": {
            "pi_a": [result.proof.a.x, result.proof.a.y, result.proof.a.z],
            "pi_b": [result.proof.b.x, result.proof.b.y, result.proof.b.z],
            "pi_c": [result.proof.c.x, result.proof.c.y, result.proof.c.z],
            "protocol": result.proof.protocol,
            "curve": result.proof.curve,
        },
        "nativeProofVerified": true,
        "javascriptProofVerified": true,
        "publicInputMutationRejects": 6,
    });
    if let Ok(path) = std::env::var("ENTROS_BOUND_NATIVE_PROOF_OUT") {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(serde_json::to_string_pretty(&output)?.as_bytes())?;
    }
    Ok(())
}

#[test]
fn rejects_a_key_with_the_bound_name_and_wrong_hash() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(std::env::var("ENTROS_BOUND_NEGATIVE_KEY_DIRECTORY")?);
    std::fs::create_dir(&directory)?;
    let key = directory.join("entros_request_bound_v1_final.zkey");
    let mut file = OpenOptions::new().write(true).create_new(true).open(&key)?;
    file.write_all(b"invalid synthetic key")?;
    let error = generate_circom_proof(
        key.to_string_lossy().into_owned(),
        "{}".to_owned(),
        ProofLib::Arkworks,
    );
    assert!(
        matches!(error, Err(entros_mopro::MoproError::CircomError(message)) if message.contains("SHA-256 mismatch"))
    );
    Ok(())
}

#[test]
fn legacy_witness_keeps_its_four_input_contract() -> Result<(), Box<dyn Error>> {
    let key = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors/circom/entros_hamming_final.zkey");
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(std::env::var(
        "ENTROS_BOUND_PROOF_FIXTURE",
    )?)?)?;
    let mut input = fixture.input;
    let object = input
        .as_object_mut()
        .ok_or("Expected a witness input object")?;
    object.remove("request_digest_hi");
    object.remove("request_digest_lo");
    let result = generate_circom_proof(
        key.to_string_lossy().into_owned(),
        input.to_string(),
        ProofLib::Arkworks,
    )?;
    assert_eq!(result.inputs, fixture.public_signals_decimal[..4]);
    assert!(verify_circom_proof(
        key.to_string_lossy().into_owned(),
        result,
        ProofLib::Arkworks
    )?);
    Ok(())
}
