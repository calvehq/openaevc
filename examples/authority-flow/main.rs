//! `cargo run -p openaevc-examples --example authority-flow`
//!
//! Delegated capabilities and revocation: root → alice (delegable) → bob.

#[tokio::main]
async fn main() -> openaevc_examples::Result<()> {
    let dir = std::env::temp_dir().join(format!("openaevc-authority-{}", std::process::id()));
    let o = openaevc_examples::authority_flow::run(&dir).await?;
    println!(
        "bob creates a pack through the delegated grant: {}",
        o.bob_before
    );
    println!(
        "bob attempts an action outside the delegation: {:?}",
        o.bob_other_action
    );
    println!("after revoking alice's grant, bob gets: {:?}", o.bob_after);
    Ok(())
}
