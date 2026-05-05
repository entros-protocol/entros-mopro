// Entros mobile prover — Rust + UniFFI surface for the circom Groth16
// hamming-distance circuit. The exported pair `generate_circom_proof` and
// `verify_circom_proof` is the entire public API; everything else is wiring
// (witness registration, UniFFI scaffolding, build-script linker hardening).

mod error;
pub use error::MoproError;

// Initialises the shared UniFFI scaffolding and registers `MoproError`.
#[cfg(not(target_arch = "wasm32"))]
mopro_ffi::app!();

// Skip `wasm_setup!()` to avoid the extern-crate alias conflict; pull
// wasm_bindgen in directly when the wasm feature is enabled.
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
use mopro_ffi::prelude::wasm_bindgen;

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn mopro_hello_world() -> String {
    "Hello, World!".to_string()
}

#[cfg_attr(
    all(feature = "wasm", target_arch = "wasm32"),
    wasm_bindgen(js_name = "moproWasmHelloWorld")
)]
pub fn mopro_wasm_hello_world() -> String {
    "Hello, World!".to_string()
}

#[cfg(test)]
mod uniffi_tests {
    #[test]
    fn test_mopro_hello_world() {
        assert_eq!(super::mopro_hello_world(), "Hello, World!");
    }
}

// Circom Groth16 wiring. The `set_circom_circuits!` registry below maps a
// zkey filename — resolved at runtime from the path the JS layer passes
// to `generateCircomProof` — to its compile-time witness function.
#[macro_use]
mod circom;
pub use circom::{
    generate_circom_proof, verify_circom_proof, CircomProof, CircomProofResult, ProofLib, G1, G2,
};

// rust-witness 0.1.6 transpiles WASM via w2c2, which strips the underscore
// from the .wasm basename when emitting C symbols (so `entros_hamming.wasm`
// → `entroshamming*` C functions). The `witness!()` macro must match the
// w2c2-emitted prefix verbatim, which is why the .wasm file is named
// `entroshamming.wasm` here. The `set_circom_circuits!` key (the zkey
// filename) is independent — it is matched at runtime against the path
// the JS layer passes — and stays as `entros_hamming_final.zkey` to
// match the bundled mobile asset.
mod witness {
    rust_witness::witness!(entroshamming);
}

crate::set_circom_circuits! {
    ("entros_hamming_final.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::entroshamming_witness)),
}
