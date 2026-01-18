use rsdebstrap::backends::mmdebstrap::MmdebstrapConfig;

/// Test helper to create a MmdebstrapConfig with minimal required fields.
///
/// All optional fields are initialized with their default values.
pub fn create_mmdebstrap(
    suite: impl Into<String>,
    target: impl Into<String>,
) -> MmdebstrapConfig {
    MmdebstrapConfig {
        suite: suite.into(),
        target: target.into(),
        mode: Default::default(),
        format: Default::default(),
        variant: Default::default(),
        architectures: Default::default(),
        components: Default::default(),
        include: Default::default(),
        keyring: Default::default(),
        aptopt: Default::default(),
        dpkgopt: Default::default(),
        setup_hook: Default::default(),
        extract_hook: Default::default(),
        essential_hook: Default::default(),
        customize_hook: Default::default(),
        mirrors: Default::default(),
    }
}
