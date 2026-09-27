//! `cargo build -p openaevc-ext-reference-kv && cargo run -p openaevc-examples --example execute-verify-promote`
//!
//! Executes a key-value change through the reference-kv extension, verifies and evaluates it,
//! qualifies it under a mandatory policy and promotes it.

#[tokio::main]
async fn main() -> openaevc_examples::Result<()> {
    let ext_dir = std::env::current_exe()?
        .parent()
        .and_then(|p| p.parent())
        .ok_or("target dir")?
        .to_path_buf();
    let dir = std::env::temp_dir().join(format!("openaevc-evp-{}", std::process::id()));
    let o = openaevc_examples::execute_verify_promote::run(&dir, &ext_dir).await?;
    println!(
        "verification {}, qualification {}, promoted {}",
        o.verification, o.qualification, o.promoted
    );
    Ok(())
}
