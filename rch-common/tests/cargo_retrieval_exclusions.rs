//! Public configuration guarantees for opt-in Cargo artifact exclusions.

use rch_common::TransferConfig;

#[test]
fn cargo_retrieval_exclude_dirs_are_opt_in_and_roundtrip_without_upload_policy() {
    let defaults: TransferConfig = toml::from_str("").unwrap();
    assert!(defaults.cargo_retrieval_exclude_dirs.is_empty());
    // A project-level empty list must survive rewrites so it continues
    // clearing an inherited user policy after serialization and reload.
    let serialized: toml::Value = toml::from_str(&toml::to_string(&defaults).unwrap()).unwrap();
    assert!(
        serialized["cargo_retrieval_exclude_dirs"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let config: TransferConfig = toml::from_str(
        r#"
exclude_patterns = ["target/", ".git/"]
cargo_retrieval_exclude_dirs = ["debug/.wrapper-shims", "release/.kache-build-script-shims"]
"#,
    )
    .unwrap();
    config.validate_cargo_retrieval_exclude_dirs().unwrap();
    assert_eq!(config.exclude_patterns, ["target/", ".git/"]);
    assert_eq!(
        config.cargo_retrieval_exclude_dirs,
        ["debug/.wrapper-shims", "release/.kache-build-script-shims"]
    );
    let roundtrip: TransferConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
    assert_eq!(roundtrip.exclude_patterns, config.exclude_patterns);
    assert_eq!(
        roundtrip.cargo_retrieval_exclude_dirs,
        config.cargo_retrieval_exclude_dirs
    );
}

#[test]
fn cargo_retrieval_exclude_dirs_require_bounded_literal_relative_paths() {
    let valid = |directory: &str| {
        TransferConfig {
            cargo_retrieval_exclude_dirs: vec![directory.into()],
            ..TransferConfig::default()
        }
        .validate_cargo_retrieval_exclude_dirs()
    };
    for directory in [
        "debug/.wrapper-shims",
        "aarch64-unknown-linux-gnu/release/.kache-build-script-shims",
        "custom profile/cache café",
    ] {
        assert!(valid(directory).is_ok(), "{directory:?}");
    }
    for directory in [
        "",
        ".",
        "..",
        "/debug/cache",
        "debug/cache/",
        "debug//cache",
        "./debug/cache",
        "debug/./cache",
        "debug/../deps",
        "../debug/cache",
        "C:/debug/cache",
        "debug\\cache",
        "debug/*",
        "debug/cach?",
        "debug/[cache]",
        "debug/cache\n",
        "debug/ca\tche",
        "debug/cache\0",
        " debug/cache",
        "debug/cache ",
    ] {
        assert!(valid(directory).is_err(), "{directory:?}");
    }
    assert!(valid(&"a".repeat(4096)).is_ok());
    assert!(valid(&"a".repeat(4097)).is_err());
    let mut config = TransferConfig {
        cargo_retrieval_exclude_dirs: (0..128)
            .map(|index| format!("debug/cache-{index}"))
            .collect(),
        ..TransferConfig::default()
    };
    config.validate_cargo_retrieval_exclude_dirs().unwrap();
    config
        .cargo_retrieval_exclude_dirs
        .push("debug/cache-128".into());
    assert!(config.validate_cargo_retrieval_exclude_dirs().is_err());
}
