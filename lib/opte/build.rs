fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(usdt_stable_asm)");
    println!("cargo::rustc-check-cfg=cfg(usdt_stable_asm_sym)");
    println!(
        "cargo::rustc-check-cfg=cfg(opte_pkt, values(\"mblk\", \"mbuf\"))"
    );

    // FreeBSD kernel builds carry packets in mbufs. The `mbuf` feature
    // selects the same backend elsewhere, with a userland allocator.
    let freebsd_kernel = std::env::var("CARGO_CFG_TARGET_OS").as_deref()
        == Ok("freebsd")
        && std::env::var_os("CARGO_FEATURE_STD").is_none();
    let mbuf =
        freebsd_kernel || std::env::var_os("CARGO_FEATURE_MBUF").is_some();
    println!(
        "cargo:rustc-cfg=opte_pkt=\"{}\"",
        if mbuf { "mbuf" } else { "mblk" }
    );

    if version_check::is_min_version("1.59").unwrap_or(false) {
        println!("cargo:rustc-cfg=usdt_stable_asm");
    }

    #[cfg(target_os = "macos")]
    if version_check::is_min_version("1.66").unwrap_or(false) {
        println!("cargo:rustc-cfg=usdt_stable_asm_sym");
    }
}
