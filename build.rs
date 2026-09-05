use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

fn copy_checked(source: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    if destination.exists() {
        if fs::read(source)? != fs::read(destination)? {
            return Err(format!("Build input changed at {}", destination.display()).into());
        }
    } else {
        fs::copy(source, destination)?;
    }
    Ok(())
}

fn prepare_w2c2(out: &Path, required: bool) -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=ENTROS_W2C2_CACHE");
    let Some(cache) = std::env::var_os("ENTROS_W2C2_CACHE") else {
        if required {
            return Err(
                "Set ENTROS_W2C2_CACHE to an existing w2c2 build for offline transpilation".into(),
            );
        }
        return Ok(());
    };
    let cache = PathBuf::from(cache);
    let target = out.join("w2c2");
    fs::create_dir_all(target.join("build/w2c2"))?;
    fs::create_dir_all(target.join("w2c2"))?;
    copy_checked(
        &cache.join("build/w2c2/w2c2"),
        &target.join("build/w2c2/w2c2"),
    )?;
    for entry in fs::read_dir(cache.join("w2c2"))? {
        let source = entry?.path();
        if source.extension().is_some_and(|extension| extension == "h") {
            let name = source.file_name().ok_or("Missing w2c2 header filename")?;
            copy_checked(&source, &target.join("w2c2").join(name))?;
        }
    }
    let mut executable_paths = vec![target.join("build/w2c2")];
    executable_paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    std::env::set_var("PATH", std::env::join_paths(executable_paths)?);
    Ok(())
}

fn required_hash(name: &str) -> Result<String, Box<dyn Error>> {
    let hash = std::env::var(name)?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must contain a lowercase SHA-256 hex digest").into());
    }
    Ok(hash)
}

fn prepare_bound_wasm(out: &Path) -> Result<String, Box<dyn Error>> {
    for name in [
        "ENTROS_BOUND_WASM_PATH",
        "ENTROS_BOUND_WASM_SHA256",
        "ENTROS_BOUND_ZKEY_SHA256",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let source = PathBuf::from(std::env::var("ENTROS_BOUND_WASM_PATH")?);
    let wasm_hash = required_hash("ENTROS_BOUND_WASM_SHA256")?;
    let key_hash = required_hash("ENTROS_BOUND_ZKEY_SHA256")?;
    if format!("{:x}", Sha256::digest(fs::read(&source)?)) != wasm_hash {
        return Err("Request-bound witness SHA-256 mismatch".into());
    }
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rustc-env=ENTROS_BOUND_ZKEY_SHA256={key_hash}");
    let inputs = out.join(format!("witness-inputs-{wasm_hash}"));
    fs::create_dir_all(&inputs)?;
    copy_checked(
        Path::new("test-vectors/circom/entroshamming.wasm"),
        &inputs.join("entroshamming.wasm"),
    )?;
    copy_checked(&source, &inputs.join("entrosrequestboundv1.wasm"))?;
    Ok(inputs.to_string_lossy().into_owned())
}

fn main() -> Result<(), Box<dyn Error>> {
    let bound = std::env::var_os("CARGO_FEATURE_REQUEST_BOUND_V1").is_some();
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    prepare_w2c2(&out, bound)?;
    let inputs = if bound {
        prepare_bound_wasm(&out)?
    } else {
        "./test-vectors/circom".to_string()
    };
    rust_witness::transpile::transpile_wasm(inputs);

    // Linker hardening below is Android-cdylib-only. It performs two jobs
    // that only apply on the Android build path:
    //
    //   1. Force whole-archive linking of libcircuit.a so the witness C
    //      functions (entroshammingInstantiate, witness_c_*, etc.) survive
    //      Rust's dead-code stripping. rust-witness's witness!() macro
    //      declares these as extern "C" inside Rust functions only reached
    //      through the mopro-ffi set_circom_circuits! registry — a
    //      registration the cdylib linker can't trace through, so
    //      libcircuit.a's contributions get GC'd and dlopen of the
    //      resulting .so fails with `cannot locate symbol "..."`.
    //
    //      `cargo:rustc-link-lib=static:+whole-archive=circuit` is rejected
    //      by cargo because transpile_wasm already emitted `static=circuit`
    //      without the modifier, so we emit raw linker args that re-link
    //      libcircuit.a inside an explicit --whole-archive bracket and
    //      pass --allow-multiple-definition for the symbol duplicates.
    //
    //   2. 16 KB page-size alignment for Android 15 / Solana Seeker. APKs
    //      containing 4 KB-aligned ELFs are rejected at install time on
    //      devices with the new page size. Verify with
    //      `llvm-readelf -l <so> | grep LOAD` — Align column should read
    //      0x4000, not 0x1000.
    //
    // Both args use GNU-ld syntax that Apple's ld and Microsoft's link.exe
    // do not understand, so we gate on TARGET to keep `cargo check`,
    // `cargo test --lib`, and IDE rust-analyzer integrations working on
    // macOS / Linux / Windows host builds.
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("android") {
        println!("cargo:rustc-link-arg=-Wl,--allow-multiple-definition");
        println!("cargo:rustc-link-arg=-Wl,--whole-archive");
        println!("cargo:rustc-link-arg=-lcircuit");
        println!("cargo:rustc-link-arg=-Wl,--no-whole-archive");
        println!("cargo:rustc-link-arg=-Wl,-z,max-page-size=16384");
    }
    Ok(())
}
