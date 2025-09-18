use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ZQLITE_PATH");

    let zqlite_path = env::var("ZQLITE_PATH").unwrap_or_else(|_| {
        "/usr/local/lib".to_string()
    });

    let include_path = env::var("ZQLITE_INCLUDE").unwrap_or_else(|_| {
        "/usr/local/include".to_string()
    });

    println!("cargo:rustc-link-search=native={}", zqlite_path);
    println!("cargo:rustc-link-lib=dylib=zqlite");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    let bindings = bindgen::Builder::default()
        .header(format!("{}/zqlite.h", include_path))
        .clang_arg(format!("-I{}", include_path))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("zqlite_.*")
        .allowlist_type("zqlite_.*")
        .allowlist_var("ZQLITE_.*")
        .generate_comments(true)
        .derive_default(true)
        .derive_debug(true)
        .generate()
        .expect("Unable to generate ZQLite bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
}