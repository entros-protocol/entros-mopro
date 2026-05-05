fn main() {
    rust_witness::transpile::transpile_wasm("./test-vectors/circom".to_string());

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
}
