use entros_mopro::{generate_circom_proof, verify_circom_proof, ProofLib};
use std::{error::Error, path::PathBuf};

#[test]
fn bundled_legacy_proof_keeps_its_four_input_contract() -> Result<(), Box<dyn Error>> {
    let key = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors/circom/entros_hamming_final.zkey")
        .to_string_lossy()
        .into_owned();
    let mut current = vec![0; 256];
    current[..10].fill(1);
    let input = serde_json::json!({
        "ft_new": current,
        "ft_prev": vec![0; 256],
        "salt_new": "1",
        "salt_prev": "2",
        "commitment_new": "5584524618015124808748202885009462765123684807017518567227693804944713088384",
        "commitment_prev": "18420563636685777789747864308564858147791528909689111727954339802617443740314",
        "threshold": "30",
        "min_distance": "3",
    });
    let result = generate_circom_proof(key.clone(), input.to_string(), ProofLib::Arkworks)?;
    assert_eq!(result.inputs.len(), 4);
    assert_eq!(
        result.inputs[0],
        input["commitment_new"]
            .as_str()
            .ok_or("Missing commitment")?
    );
    assert!(verify_circom_proof(
        key.clone(),
        result,
        ProofLib::Arkworks
    )?);
    for mutation in [
        serde_json::json!({ "commitment_new": "123" }),
        serde_json::json!({ "threshold": "3" }),
    ] {
        let mut invalid = input.clone();
        for (name, value) in mutation.as_object().ok_or("Missing mutation")? {
            invalid[name] = value.clone();
        }
        assert!(
            generate_circom_proof(key.clone(), invalid.to_string(), ProofLib::Arkworks).is_err()
        );
    }
    Ok(())
}
