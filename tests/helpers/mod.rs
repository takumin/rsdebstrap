use rsdebstrap::backends::debootstrap::DebootstrapConfig;
use rsdebstrap::backends::mmdebstrap::MmdebstrapConfig;
use rsdebstrap::config::{Bootstrap, Profile};

/// Test helper to create a MmdebstrapConfig with minimal required fields.
///
/// All optional fields are initialized with their default values.
#[allow(dead_code)]
pub fn create_mmdebstrap(suite: impl Into<String>, target: impl Into<String>) -> MmdebstrapConfig {
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

/// Test helper to create a DebootstrapConfig with minimal required fields.
///
/// All optional fields are initialized with their default values.
#[allow(dead_code)]
pub fn create_debootstrap(
    suite: impl Into<String>,
    target: impl Into<String>,
) -> DebootstrapConfig {
    DebootstrapConfig {
        suite: suite.into(),
        target: target.into(),
        variant: Default::default(),
        arch: Default::default(),
        components: Default::default(),
        include: Default::default(),
        exclude: Default::default(),
        mirror: Default::default(),
        foreign: Default::default(),
        merged_usr: Default::default(),
        no_resolve_deps: Default::default(),
        verbose: Default::default(),
        print_debs: Default::default(),
    }
}

/// Extracts MmdebstrapConfig from a Profile, panicking if it's not the mmdebstrap backend.
///
/// # Panics
/// Panics if the profile's bootstrap type is not mmdebstrap.
#[allow(dead_code)]
pub fn get_mmdebstrap_config(profile: &Profile) -> &MmdebstrapConfig {
    if let Bootstrap::Mmdebstrap(cfg) = &profile.bootstrap {
        cfg
    } else {
        panic!("Expected mmdebstrap bootstrap type");
    }
}

/// Extracts DebootstrapConfig from a Profile, panicking if it's not the debootstrap backend.
///
/// # Panics
/// Panics if the profile's bootstrap type is not debootstrap.
#[allow(dead_code)]
pub fn get_debootstrap_config(profile: &Profile) -> &DebootstrapConfig {
    if let Bootstrap::Debootstrap(cfg) = &profile.bootstrap {
        cfg
    } else {
        panic!("Expected debootstrap bootstrap type");
    }
}
