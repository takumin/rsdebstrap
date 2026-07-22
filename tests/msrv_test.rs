//! Guards the declared MSRV (`rust-version`) against drift from the pinned `rust-toolchain.toml`.
//! Rationale: `docs/ARCHITECTURE.md` (MSRV policy).

/// The pinned `channel` value from `rust-toolchain.toml` (e.g. `"1.97.1"`).
fn pinned_channel() -> &'static str {
    let toolchain = include_str!("../rust-toolchain.toml");
    toolchain
        .lines()
        .find_map(|line| {
            let rest = line.trim().strip_prefix("channel")?.trim_start();
            let value = rest.strip_prefix('=')?.trim();
            value.strip_prefix('"')?.split('"').next()
        })
        .expect("rust-toolchain.toml must declare channel = \"...\"")
}

/// Numeric dotted-version components, e.g. `"1.97.1"` -> `[1, 97, 1]`.
fn version_parts(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|part| {
            part.parse::<u64>()
                .expect("version component must be numeric")
        })
        .collect()
}

#[test]
fn declared_msrv_matches_pinned_toolchain() {
    let msrv_str = env!("CARGO_PKG_RUST_VERSION");
    assert!(
        !msrv_str.is_empty(),
        "Cargo.toml must declare a `rust-version` (the MSRV) in [package]"
    );
    let channel_str = pinned_channel();

    let msrv = version_parts(msrv_str);
    let channel = version_parts(channel_str);

    assert!(msrv.len() >= 2, "rust-version must specify at least major.minor");
    assert_eq!(
        channel.len(),
        3,
        "rust-toolchain.toml channel must pin an exact patch release (major.minor.patch)",
    );
    assert_eq!(
        (msrv[0], msrv[1]),
        (channel[0], channel[1]),
        concat!(
            "MSRV drift: rust-version \"{}\" and rust-toolchain.toml channel \"{}\" differ in ",
            "major.minor; update rust-version when the pinned toolchain's minor changes."
        ),
        msrv_str,
        channel_str,
    );
}
