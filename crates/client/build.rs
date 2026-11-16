use std::path::Path;

/// Копирует vendor/wintun/wintun.dll рядом с exe (target/<profile>/wintun.dll),
/// чтобы клиент находил драйвер без ручных шагов.
fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let src = Path::new(&manifest).join("../../vendor/wintun/wintun.dll");
    println!("cargo:rerun-if-changed=../../vendor/wintun/wintun.dll");
    if let Ok(out) = std::env::var("OUT_DIR")
        && let Some(profile_dir) = Path::new(&out).ancestors().nth(3)
        && src.exists()
    {
        let dst = profile_dir.join("wintun.dll");
        let _ = std::fs::copy(&src, dst);
    }
}
