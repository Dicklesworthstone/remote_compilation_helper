use rch_common::RchConfig;

use super::common::init_test_logging;

#[test]
fn test_default_config_enabled() {
    init_test_logging();
    crate::test_log!("TEST START: test_default_config_enabled");

    let config = RchConfig::default();
    assert!(
        config.general.enabled,
        "Expected RCH to be enabled by default"
    );

    crate::test_log!("TEST PASS: test_default_config_enabled");
}
