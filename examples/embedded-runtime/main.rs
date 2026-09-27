//! `cargo run -p openaevc-examples --example embedded-runtime`
//!
//! Embeds the runtime in-process over a temporary SQLite data root and takes a change from
//! creation to an immutable Baseline.

#[tokio::main]
async fn main() -> openaevc_examples::Result<()> {
    let dir = std::env::temp_dir().join(format!("openaevc-embedded-{}", std::process::id()));
    let s = openaevc_examples::embedded_runtime::run(&dir).await?;
    println!(
        "promoted pack {}\nbaseline {} (valid: {})\ndata root {}",
        s.promoted,
        s.baseline,
        s.valid,
        dir.display()
    );
    Ok(())
}
