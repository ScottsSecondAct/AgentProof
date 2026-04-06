//! Build script: runs cbindgen to emit `aegis.h` alongside the compiled library.
//!
//! The generated header is written to the crate root (`aegis-ffi/aegis.h`) so
//! it can be committed and consumed by downstream language SDKs without
//! requiring cbindgen to be installed in their build environments.

fn main() {
    let crate_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    let config = cbindgen::Config::from_file(
        std::path::Path::new(&crate_dir).join("cbindgen.toml"),
    )
    .expect("failed to read cbindgen.toml");

    // Write header to the crate root; committed to source control.
    let output_path = std::path::Path::new(&crate_dir).join("aegis.h");

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen failed to generate C bindings")
        .write_to_file(output_path);

    // Re-run this script only when the FFI source changes.
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
