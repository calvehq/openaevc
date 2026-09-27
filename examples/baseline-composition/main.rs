//! `cargo build -p openaevc-ext-reference-kv && cargo run -p openaevc-examples --example baseline-composition`
//!
//! Independent Baselines sharing promoted packs; a key-value conflict needs an explicit ordering.

#[tokio::main]
async fn main() -> openaevc_examples::Result<()> {
    let ext_dir = std::env::current_exe()?
        .parent()
        .and_then(|p| p.parent())
        .ok_or("target dir")?
        .to_path_buf();
    let dir = std::env::temp_dir().join(format!("openaevc-composition-{}", std::process::id()));
    let o = openaevc_examples::baseline_composition::run(&dir, &ext_dir).await?;
    println!("unordered conflicting packs: {:?}", o.unordered_conflict);
    println!("with an ORDERS_AFTER edge: baseline {}", o.ordered);
    println!("independent baselines sharing packs: {:?}", o.independent);
    Ok(())
}
