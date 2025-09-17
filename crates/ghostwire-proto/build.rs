use std::io::Result;

fn main() -> Result<()> {
    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&["src/coordination.proto"], &["src"])?;

    Ok(())
}