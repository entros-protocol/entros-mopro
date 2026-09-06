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

#[test]
fn rejects_malformed_proof_points_without_panicking() -> Result<(), Box<dyn Error>> {
    let key = std::env::var("ENTROS_BOUND_ZKEY_PATH")?;
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(std::env::var(
        "ENTROS_BOUND_PROOF_FIXTURE",
    )?)?)?;
    let [x, y, z] = fixture.proof.pi_b;
    let valid = CircomProofResult {
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
        valid.clone(),
        ProofLib::Arkworks
    )?);
    let mut off_curve = valid.clone();
    off_curve.proof.a.x = "1".to_owned();
    off_curve.proof.a.y = "1".to_owned();
    let outcome = std::panic::catch_unwind(|| {
        verify_circom_proof(key.clone(), off_curve, ProofLib::Arkworks)
    });
    assert!(
        matches!(outcome, Ok(Ok(false)) | Ok(Err(_))),
        "Malformed point must reject without panic: {outcome:?}"
    );
    let modulus: num_bigint::BigUint =
        "21888242871839275222246405745257275088696311157297823662689037894645226208583".parse()?;
    let mut aliased = valid.clone();
    let coordinate: num_bigint::BigUint = aliased.proof.a.x.parse()?;
    aliased.proof.a.x = (coordinate + modulus).to_string();
    assert!(matches!(
        verify_circom_proof(key.clone(), aliased, ProofLib::Arkworks),
        Ok(false) | Err(_)
    ));
    let mut wrong_projective = valid.clone();
    wrong_projective.proof.a.z = "2".to_owned();
    assert!(matches!(
        verify_circom_proof(key.clone(), wrong_projective, ProofLib::Arkworks),
        Ok(false) | Err(_)
    ));
    let mut mutations = Vec::new();
    for index in 0..8 {
        let mut changed = valid.clone();
        let coordinate = match index {
            0 => &mut changed.proof.a.x,
            1 => &mut changed.proof.a.y,
            2 => &mut changed.proof.b.x[0],
            3 => &mut changed.proof.b.x[1],
            4 => &mut changed.proof.b.y[0],
            5 => &mut changed.proof.b.y[1],
            6 => &mut changed.proof.c.x,
            _ => &mut changed.proof.c.y,
        };
        let base: num_bigint::BigUint = coordinate.parse()?;
        let modulus: num_bigint::BigUint =
            "21888242871839275222246405745257275088696311157297823662689037894645226208583"
                .parse()?;
        *coordinate = (base + modulus).to_string();
        mutations.push(changed);
    }
    let mut infinity = valid.clone();
    infinity.proof.a = G1 {
        x: "0".into(),
        y: "0".into(),
        z: "0".into(),
    };
    mutations.push(infinity);
    let mut infinity = valid.clone();
    infinity.proof.b = G2 {
        x: vec!["0".into(), "0".into()],
        y: vec!["0".into(), "0".into()],
        z: vec!["0".into(), "0".into()],
    };
    mutations.push(infinity);
    let mut subgroup = valid.clone();
    let point = (0u64..100)
        .find_map(|value| {
            ark_bn254::G2Affine::get_point_from_x_unchecked(
                ark_bn254::Fq2::new(value.into(), 1u64.into()),
                false,
            )
            .filter(|point| !point.is_in_correct_subgroup_assuming_on_curve())
        })
        .ok_or("Missing wrong-subgroup test point")?;
    assert!(point.is_on_curve());
    subgroup.proof.b = G2 {
        x: vec![point.x.c0.to_string(), point.x.c1.to_string()],
        y: vec![point.y.c0.to_string(), point.y.c1.to_string()],
        z: vec!["1".into(), "0".into()],
    };
    mutations.push(subgroup);
    let mut metadata = valid.clone();
    metadata.proof.curve = "bls12381".into();
    mutations.push(metadata);
    let mut metadata = valid;
    metadata.proof.protocol = "plonk".into();
    mutations.push(metadata);
    for changed in mutations {
        let outcome = std::panic::catch_unwind(|| {
            verify_circom_proof(key.clone(), changed, ProofLib::Arkworks)
        });
        assert!(
            matches!(outcome, Ok(Ok(false)) | Ok(Err(_))),
            "Malformed proof must reject without panic: {outcome:?}"
        );
    }
    Ok(())
}

#[test]
fn concurrent_requests_keep_their_own_public_inputs() -> Result<(), Box<dyn Error>> {
    let key = std::env::var("ENTROS_BOUND_ZKEY_PATH")?;
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(std::env::var(
        "ENTROS_BOUND_PROOF_FIXTURE",
    )?)?)?;
    let started = std::time::Instant::now();
    let results = std::thread::scope(|scope| {
        let workers = (0..2)
            .map(|worker| {
                let key = &key;
                let input = &fixture.input;
                scope.spawn(move || -> Result<(), String> {
                    for sequence in 0..4 {
                        let mut request = input.clone();
                        let limb = (worker * 4 + sequence + 1).to_string();
                        request["request_digest_hi"] = serde_json::Value::String(limb.clone());
                        let proof_started = std::time::Instant::now();
                        let result = generate_circom_proof(
                            key.clone(),
                            request.to_string(),
                            ProofLib::Arkworks,
                        )
                        .map_err(|error| error.to_string())?;
                        if result.inputs.get(4) != Some(&limb) {
                            return Err("Concurrent requests exchanged public inputs".to_owned());
                        }
                        let proof_ms = proof_started.elapsed().as_millis();
                        let verification_started = std::time::Instant::now();
                        for _ in 0..4 {
                            if !verify_circom_proof(key.clone(), result.clone(), ProofLib::Arkworks)
                                .map_err(|error| error.to_string())?
                            {
                                return Err("Concurrent proof verification failed".to_owned());
                            }
                        }
                        println!("Host synthetic request: worker={worker} sequence={sequence} generate_ms={proof_ms} verify_four_ms={}", verification_started.elapsed().as_millis());
                    }
                    Ok(())
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|worker| worker.join())
            .collect::<Vec<_>>()
    });
    for result in results {
        result
            .map_err(|_| "Concurrent prover panicked")?
            .map_err(std::io::Error::other)?;
    }
    println!(
        "Host synthetic pressure: workers=2 proofs=8 verifications=32 elapsed_ms={}",
        started.elapsed().as_millis()
    );
    Ok(())
}

#[test]
fn rejects_a_witness_with_a_wrong_commitment() -> Result<(), Box<dyn Error>> {
    let key = std::env::var("ENTROS_BOUND_ZKEY_PATH")?;
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(std::env::var(
        "ENTROS_BOUND_PROOF_FIXTURE",
    )?)?)?;
    let mut input = fixture.input;
    input["commitment_new"] = serde_json::Value::String("123".to_owned());
    let outcome = std::panic::catch_unwind(|| {
        generate_circom_proof(key.clone(), input.to_string(), ProofLib::Arkworks)
    });
    if let Ok(Ok(result)) = &outcome {
        let verifies = verify_circom_proof(key, result.clone(), ProofLib::Arkworks)?;
        println!("Invalid witness returned proof; verifies={verifies}");
        assert!(!verifies, "Invalid witness must not yield a valid proof");
    }
    assert!(
        matches!(outcome, Ok(Err(_))),
        "Invalid witness must return an error: {outcome:?}"
    );
    Ok(())
}

#[test]
fn rejects_a_malformed_legacy_key_without_panicking() -> Result<(), Box<dyn Error>> {
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(std::env::var(
        "ENTROS_BOUND_PROOF_FIXTURE",
    )?)?)?;
    let [x, y, z] = fixture.proof.pi_b;
    let result = CircomProofResult {
        inputs: fixture.public_signals_decimal[..4].to_vec(),
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
    let directory = PathBuf::from(format!(
        "{}-legacy",
        std::env::var("ENTROS_BOUND_NEGATIVE_KEY_DIRECTORY")?
    ));
    std::fs::create_dir(&directory)?;
    let key = directory.join("entros_hamming_final.zkey");
    let mut file = OpenOptions::new().write(true).create_new(true).open(&key)?;
    file.write_all(b"invalid synthetic key")?;
    let outcome = std::panic::catch_unwind(|| {
        verify_circom_proof(
            key.to_string_lossy().into_owned(),
            result,
            ProofLib::Arkworks,
        )
    });
    assert!(
        matches!(outcome, Ok(Err(_))),
        "Invalid key must return an error: {outcome:?}"
    );
    Ok(())
}
