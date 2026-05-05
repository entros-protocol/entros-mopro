# entros-mopro

Mobile prover for the Entros Protocol Hamming-distance Groth16 circuit. Wraps [mopro](https://zkmopro.org) (Rust + arkworks + UniFFI) to produce React Native native bindings that prove `Hamming(fingerprint_new, fingerprint_baseline) < threshold` on-device, without sending the underlying 256-bit fingerprint anywhere.

The circuit itself lives in [entros-protocol/circuits](https://github.com/entros-protocol/circuits) (`circom/entros_hamming.circom`). This repo packages the proving artifacts into a `.so` + UniFFI bindings consumed by [entros-protocol/entros-mobile](https://github.com/entros-protocol/entros-mobile).

## Status

Stable build tooling. Regenerated only when the underlying circuit changes. The vendored output (`MoproReactNativeBindings/`) is gitignored here and held by the consumer (entros-mobile).

## Repo layout

```
src/
├── lib.rs            # Registers the entroshamming witness with mopro-ffi
├── circom.rs         # generate_circom_proof / verify_circom_proof glue
├── error.rs          # MoproError enum (CircomError variant)
└── bin/              # Mopro build-command wrappers (android / ios / web / flutter)
build.rs              # Whole-archive linker fix (see "Gotchas" below)
Cargo.toml            # mopro-ffi 0.3.4 + circom-prover 0.1 + rust-witness 0.1
Config.toml           # mopro adapter + target config (circom + react-native)
test-vectors/circom/
├── entros_hamming_final.zkey  # 894 KB Groth16 proving key (public artifact)
└── entroshamming.wasm         # Compiled witness calculator
tests/                # UniFFI cross-language smoke (Kotlin + Swift FFI bridge)
```

## Building

Prerequisites: Rust 1.88+, Android NDK 26.1.10909125, JDK 21, mopro-cli 0.3.5, and `uniffi-bindgen-react-native` 0.29.3-1 from the upstream git tag.

This crate ships native bindings — bindings are produced by `mopro build`, not `cargo build`. Direct `cargo build` works for source-level type-checking and the unit test in `src/lib.rs`, but it does not emit the consumable `MoproReactNativeBindings/` output. Use `mopro build` for any output you intend to vendor into a mobile app.

```sh
# Install matching uniffi-bindgen-react-native (the published binary may be
# stale relative to the Rust uniffi crate version mopro requires).
cargo install --git https://github.com/jhugman/uniffi-bindgen-react-native --tag 0.29.3-1 uniffi-bindgen-react-native

# Build the React Native bindings for arm64 Android (release).
ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/26.1.10909125" \
ANDROID_HOME="$HOME/Library/Android/sdk" \
mopro build --mode release --platforms react-native --architectures aarch64-linux-android --no-auto-update
```

Output: `MoproReactNativeBindings/` (~5 MB; 4.8 MB is `libentros_mopro.so`).

## Vendoring into entros-mobile

```sh
rm -rf /path/to/entros-mobile/MoproReactNativeBindings
cp -r MoproReactNativeBindings /path/to/entros-mobile/

# Restore the mobile-side .gitignore overrides (cp clobbers them).
# Then edit MoproReactNativeBindings/package.json:
#   - Set "main": "./src/index.tsx"
#   - Drop the "lib/" entries from "exports" (the consumer compiles
#     src/ on the fly via Metro+Babel; lib/ is not shipped).
```

## Gotchas

### Whole-archive linker fix

`build.rs` emits raw linker args to force `libcircuit.a` into the cdylib via `-Wl,--whole-archive` + `--no-whole-archive`, with `--allow-multiple-definition` to accept the symbol duplicates from the two link passes.

Without this, all 239 `entroshamming*` and `witness_c_*` C symbols get garbage-collected during cdylib link because the only Rust call sites — inside `rust-witness`'s `witness!()` macro and `mopro-ffi`'s `set_circom_circuits!` registry — are unreachable to the cdylib linker. The resulting `.so` then fails to `dlopen` with `cannot locate symbol entros_hammingInstantiate`.

### Wasm basename rename

`rust-witness` 0.1.6 transpiles WASM via w2c2, which strips underscores from the `.wasm` basename when emitting C symbols. `entros_hamming.wasm` would emit `entroshamming*` C functions, and the `witness!()` macro needs the basename to match the C symbol prefix verbatim.

So the `.wasm` is renamed to `entroshamming.wasm` before mopro processes it. The `set_circom_circuits!` lookup key (`entros_hamming_final.zkey`) is independent — it's matched at runtime against the path the JS side passes — and stays as `entros_hamming_final.zkey` to match the bundled mobile asset.

### 16 KB page size alignment

Android 15 (which Solana Seeker ships) requires `.so` LOAD segments to be aligned to a 16 KB boundary. APKs containing 4 KB-aligned ELFs are rejected at install time on devices with the new page size.

`build.rs` emits `-Wl,-z,max-page-size=16384` alongside the whole-archive args. Verify after a regen:

```sh
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf -l \
  MoproReactNativeBindings/android/src/main/jniLibs/arm64-v8a/libentros_mopro.so | grep LOAD
```

The `Align` column on each LOAD segment should read `0x4000` (16384), not `0x1000` (4096).

### `uniffi-bindgen-react-native` version pin

mopro 0.3.5 expects the Rust uniffi crate's 0.29 contract version. `cargo install uniffi-bindgen-react-native` from crates.io may install a stale binary (e.g. 0.31.0-2) that emits bindings against a different ABI, leading to checksum mismatches at runtime. Always install from the git tag: `--git https://github.com/jhugman/uniffi-bindgen-react-native --tag 0.29.3-1`.

## License

MIT — see [LICENSE](LICENSE).
