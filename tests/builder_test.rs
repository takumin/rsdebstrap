use camino::Utf8PathBuf;
use rsdebstrap::config::{Format, Mmdebstrap, Mode, Profile, Variant};
use std::ffi::OsString;

#[test]
fn test_build_mmdebstrap_args_minimal() {
    // Create a minimal profile with just required fields
    let profile = Profile {
        dir: Utf8PathBuf::from("/tmp"),
        mmdebstrap: Mmdebstrap {
            suite: "bookworm".to_string(),
            target: "output.tar".to_string(),
            mode: Mode::Auto,
            format: Format::Auto,
            variant: Variant::Debootstrap,
            architectures: vec![],
            components: vec![],
            include: vec![],
            keyring: vec![],
            aptopt: vec![],
            dpkgopt: vec![],
            setup_hook: vec![],
            extract_hook: vec![],
            essential_hook: vec![],
            customize_hook: vec![],
        },
    };

    let args = rsdebstrap::builder::build_mmdebstrap_args(&profile);

    // Check required args are present
    assert_eq!(args.len(), 8); // 3 flags with values + suite + target
    assert_eq!(args[0], OsString::from("--mode"));
    assert_eq!(args[1], OsString::from("auto"));
    assert_eq!(args[2], OsString::from("--format"));
    assert_eq!(args[3], OsString::from("auto"));
    assert_eq!(args[4], OsString::from("--variant"));
    assert_eq!(args[5], OsString::from("debootstrap"));
    assert_eq!(args[6], OsString::from("bookworm"));
    assert_eq!(args[7], OsString::from("/tmp/output.tar"));
}

#[test]
fn test_build_mmdebstrap_args_full() {
    let profile = Profile {
        dir: Utf8PathBuf::from("/mnt/images"),
        mmdebstrap: Mmdebstrap {
            suite: "bookworm".to_string(),
            target: "debian-bookworm.tar.gz".to_string(),
            mode: Mode::Sudo,
            format: Format::TarGz,
            variant: Variant::Standard,
            architectures: vec!["amd64".to_string()],
            components: vec!["main".to_string(), "contrib".to_string()],
            include: vec!["vim".to_string(), "curl".to_string()],
            keyring: vec!["/path/to/keyring.gpg".to_string()],
            aptopt: vec!["--option=Debug::pkgProblemResolver=true".to_string()],
            dpkgopt: vec!["--force-confnew".to_string()],
            setup_hook: vec!["/path/to/setup.sh".to_string()],
            extract_hook: vec!["/path/to/extract.sh".to_string()],
            essential_hook: vec!["/path/to/essential.sh".to_string()],
            customize_hook: vec!["/path/to/customize.sh".to_string()],
        },
    };

    let args = rsdebstrap::builder::build_mmdebstrap_args(&profile);

    // Check for expected number of arguments
    assert_eq!(args.len(), 28); // 13 flags with values + suite + target

    // Check mode, format, variant
    assert_eq!(args[0], OsString::from("--mode"));
    assert_eq!(args[1], OsString::from("sudo"));
    assert_eq!(args[2], OsString::from("--format"));
    assert_eq!(args[3], OsString::from("tar.gz"));
    assert_eq!(args[4], OsString::from("--variant"));
    assert_eq!(args[5], OsString::from("standard"));

    // Check architectures, components, include
    assert_eq!(args[6], OsString::from("--architectures"));
    assert_eq!(args[7], OsString::from("amd64"));
    assert_eq!(args[8], OsString::from("--components"));
    assert_eq!(args[9], OsString::from("main,contrib"));
    assert_eq!(args[10], OsString::from("--include"));
    assert_eq!(args[11], OsString::from("vim,curl"));

    // Check keyring
    assert_eq!(args[12], OsString::from("--keyring"));
    assert_eq!(args[13], OsString::from("/path/to/keyring.gpg"));

    // Check aptopt
    assert_eq!(args[14], OsString::from("--aptopt"));
    assert_eq!(args[15], OsString::from("--option=Debug::pkgProblemResolver=true"));

    // Check dpkgopt
    assert_eq!(args[16], OsString::from("--dpkgopt"));
    assert_eq!(args[17], OsString::from("--force-confnew"));

    // Check hooks
    assert_eq!(args[18], OsString::from("--setup-hook"));
    assert_eq!(args[19], OsString::from("/path/to/setup.sh"));
    assert_eq!(args[20], OsString::from("--extract-hook"));
    assert_eq!(args[21], OsString::from("/path/to/extract.sh"));
    assert_eq!(args[22], OsString::from("--essential-hook"));
    assert_eq!(args[23], OsString::from("/path/to/essential.sh"));
    assert_eq!(args[24], OsString::from("--customize-hook"));
    assert_eq!(args[25], OsString::from("/path/to/customize.sh"));

    // Check suite and target
    assert_eq!(args[26], OsString::from("bookworm"));
    assert_eq!(args[27], OsString::from("/mnt/images/debian-bookworm.tar.gz"));
}

#[test]
fn test_build_mmdebstrap_args_empty_values() {
    // Test that empty values don't generate arguments
    let profile = Profile {
        dir: Utf8PathBuf::from("/tmp"),
        mmdebstrap: Mmdebstrap {
            suite: "bookworm".to_string(),
            target: "output.tar".to_string(),
            mode: Mode::Auto,
            format: Format::Auto,
            variant: Variant::Debootstrap,
            // Empty vectors - should not generate flags
            architectures: vec!["".to_string()],
            components: vec!["".to_string()],
            include: vec!["".to_string()],
            // These are already empty vectors
            keyring: vec![],
            aptopt: vec![],
            dpkgopt: vec![],
            setup_hook: vec![],
            extract_hook: vec![],
            essential_hook: vec![],
            customize_hook: vec![],
        },
    };

    let args = rsdebstrap::builder::build_mmdebstrap_args(&profile);

    // Check only required args are present (should skip empty values)
    assert_eq!(args.len(), 8);
    assert_eq!(args[0], OsString::from("--mode"));
    assert_eq!(args[1], OsString::from("auto"));
    assert_eq!(args[2], OsString::from("--format"));
    assert_eq!(args[3], OsString::from("auto"));
    assert_eq!(args[4], OsString::from("--variant"));
    assert_eq!(args[5], OsString::from("debootstrap"));
    assert_eq!(args[6], OsString::from("bookworm"));
    assert_eq!(args[7], OsString::from("/tmp/output.tar"));
}

#[test]
fn test_build_mmdebstrap_args_multiple_flags() {
    // Test multiple values for the same flag
    let profile = Profile {
        dir: Utf8PathBuf::from("/tmp"),
        mmdebstrap: Mmdebstrap {
            suite: "bookworm".to_string(),
            target: "output.tar".to_string(),
            mode: Mode::Auto,
            format: Format::Auto,
            variant: Variant::Debootstrap,
            architectures: vec![],
            components: vec![],
            include: vec![],
            // Multiple values for the same flag
            keyring: vec![
                "/path/to/keyring1.gpg".to_string(),
                "/path/to/keyring2.gpg".to_string(),
            ],
            aptopt: vec![],
            dpkgopt: vec![],
            setup_hook: vec![],
            extract_hook: vec![],
            essential_hook: vec![],
            customize_hook: vec![
                "/path/to/hook1.sh".to_string(),
                "/path/to/hook2.sh".to_string(),
                "/path/to/hook3.sh".to_string(),
            ],
        },
    };

    let args = rsdebstrap::builder::build_mmdebstrap_args(&profile);

    // Check required args plus multiple flag values
    // 3 base flags + 2 keyring + 3 customize + suite + target = 9 pairs = 18
    assert_eq!(args.len(), 18);

    // Check keyring flags (should be repeated for each value)
    let keyring_indices = args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.to_string_lossy() == "--keyring")
        .map(|(i, _)| i)
        .collect::<Vec<_>>();

    assert_eq!(keyring_indices.len(), 2);
    assert_eq!(args[keyring_indices[0] + 1], OsString::from("/path/to/keyring1.gpg"));
    assert_eq!(args[keyring_indices[1] + 1], OsString::from("/path/to/keyring2.gpg"));

    // Check customize hook flags
    let customize_indices = args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.to_string_lossy() == "--customize-hook")
        .map(|(i, _)| i)
        .collect::<Vec<_>>();

    assert_eq!(customize_indices.len(), 3);
    assert_eq!(args[customize_indices[0] + 1], OsString::from("/path/to/hook1.sh"));
    assert_eq!(args[customize_indices[1] + 1], OsString::from("/path/to/hook2.sh"));
    assert_eq!(args[customize_indices[2] + 1], OsString::from("/path/to/hook3.sh"));
}

#[test]
fn test_build_mmdebstrap_args_different_variants() {
    // Test different variants
    let variants = vec![
        (Variant::Extract, "extract"),
        (Variant::Custom, "custom"),
        (Variant::Essential, "essential"),
        (Variant::Apt, "apt"),
        (Variant::Buildd, "buildd"),
        (Variant::Required, "required"),
        (Variant::Minbase, "minbase"),
        (Variant::Important, "important"),
        (Variant::Standard, "standard"),
    ];

    for (variant, expected_str) in variants {
        let profile = Profile {
            dir: Utf8PathBuf::from("/tmp"),
            mmdebstrap: Mmdebstrap {
                suite: "bookworm".to_string(),
                target: "output.tar".to_string(),
                mode: Mode::Auto,
                format: Format::Auto,
                variant,
                architectures: vec![],
                components: vec![],
                include: vec![],
                keyring: vec![],
                aptopt: vec![],
                dpkgopt: vec![],
                setup_hook: vec![],
                extract_hook: vec![],
                essential_hook: vec![],
                customize_hook: vec![],
            },
        };

        let args = rsdebstrap::builder::build_mmdebstrap_args(&profile);

        // Check variant is correctly set
        assert_eq!(args[4], OsString::from("--variant"));
        assert_eq!(args[5], OsString::from(expected_str));
    }
}

#[test]
fn test_build_mmdebstrap_args_different_modes() {
    // Test different modes
    let modes = vec![
        (Mode::Sudo, "sudo"),
        (Mode::Root, "root"),
        (Mode::Unshare, "unshare"),
        (Mode::Fakeroot, "fakeroot"),
        (Mode::Fakechroot, "fakechroot"),
        (Mode::Chrootless, "chrootless"),
    ];

    for (mode, expected_str) in modes {
        let profile = Profile {
            dir: Utf8PathBuf::from("/tmp"),
            mmdebstrap: Mmdebstrap {
                suite: "bookworm".to_string(),
                target: "output.tar".to_string(),
                mode,
                format: Format::Auto,
                variant: Variant::Debootstrap,
                architectures: vec![],
                components: vec![],
                include: vec![],
                keyring: vec![],
                aptopt: vec![],
                dpkgopt: vec![],
                setup_hook: vec![],
                extract_hook: vec![],
                essential_hook: vec![],
                customize_hook: vec![],
            },
        };

        let args = rsdebstrap::builder::build_mmdebstrap_args(&profile);

        // Check mode is correctly set
        assert_eq!(args[0], OsString::from("--mode"));
        assert_eq!(args[1], OsString::from(expected_str));
    }
}

#[test]
fn test_build_mmdebstrap_args_different_formats() {
    // Test different formats
    let formats = vec![
        (Format::Directory, "directory"),
        (Format::Tar, "tar"),
        (Format::TarXz, "tar.xz"),
        (Format::TarGz, "tar.gz"),
        (Format::TarZst, "tar.zst"),
        (Format::Squashfs, "squashfs"),
        (Format::Ext2, "ext2"),
        (Format::Null, "null"),
    ];

    for (format, expected_str) in formats {
        let profile = Profile {
            dir: Utf8PathBuf::from("/tmp"),
            mmdebstrap: Mmdebstrap {
                suite: "bookworm".to_string(),
                target: "output.tar".to_string(),
                mode: Mode::Auto,
                format,
                variant: Variant::Debootstrap,
                architectures: vec![],
                components: vec![],
                include: vec![],
                keyring: vec![],
                aptopt: vec![],
                dpkgopt: vec![],
                setup_hook: vec![],
                extract_hook: vec![],
                essential_hook: vec![],
                customize_hook: vec![],
            },
        };

        let args = rsdebstrap::builder::build_mmdebstrap_args(&profile);

        // Check format is correctly set
        assert_eq!(args[2], OsString::from("--format"));
        assert_eq!(args[3], OsString::from(expected_str));
    }
}

#[test]
fn test_build_mmdebstrap_args_edge_cases() {
    // Test with mix of empty and non-empty values
    let profile = Profile {
        dir: Utf8PathBuf::from("/tmp"),
        mmdebstrap: Mmdebstrap {
            suite: "bookworm".to_string(),
            target: "output.tar".to_string(),
            mode: Mode::Auto,
            format: Format::Auto,
            variant: Variant::Debootstrap,
            architectures: vec!["amd64".to_string()],
            components: vec![],
            include: vec!["vim".to_string()],
            keyring: vec!["".to_string()],
            aptopt: vec!["--option=Value".to_string(), "".to_string()],
            dpkgopt: vec![],
            setup_hook: vec![],
            extract_hook: vec![],
            essential_hook: vec![],
            customize_hook: vec![],
        },
    };

    let args = rsdebstrap::builder::build_mmdebstrap_args(&profile);

    // Check that empty strings are skipped but non-empty values are included
    let include_indices = args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.to_string_lossy() == "--include")
        .map(|(i, _)| i)
        .collect::<Vec<_>>();

    assert_eq!(include_indices.len(), 1);
    assert_eq!(args[include_indices[0] + 1], OsString::from("vim"));

    let aptopt_indices = args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.to_string_lossy() == "--aptopt")
        .map(|(i, _)| i)
        .collect::<Vec<_>>();

    assert_eq!(aptopt_indices.len(), 1);
    assert_eq!(args[aptopt_indices[0] + 1], OsString::from("--option=Value"));

    // Keyring with only empty string should be skipped entirely
    let keyring_indices = args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.to_string_lossy() == "--keyring")
        .map(|(i, _)| i)
        .collect::<Vec<_>>();

    assert_eq!(keyring_indices.len(), 0);
}
