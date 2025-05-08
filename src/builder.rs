use crate::config::Profile;
use std::ffi::OsString;
use tracing::debug;

/// Adds a flag and its corresponding value to the command arguments if the value is not empty.
///
/// # Parameters
/// - `cmd_args`: A mutable reference to the vector of command arguments.
/// - `flag`: The flag to be added (e.g., `--mode`).
/// - `value`: The value associated with the flag. This value should already be trimmed.
///
/// # Behavior
/// If `value` is an empty string, the flag and value are not added to `cmd_args`.
fn add_flag(cmd_args: &mut Vec<OsString>, flag: &str, value: &str) {
    if !value.is_empty() {
        cmd_args.push(flag.into());
        cmd_args.push(value.into());
    }
}

/// Adds a flag and its associated values to the command arguments.
///
/// This function iterates over the provided `values` slice and, for each non-empty string,
/// appends the `flag` and the `value` to the `cmd_args` vector. It does not perform any
/// trimming or preprocessing on the `values`; the caller is responsible for ensuring that
/// the input is in the desired format.
///
/// # Arguments
/// * `cmd_args` - A mutable reference to the vector of command-line arguments.
/// * `flag` - The flag to be added for each value.
/// * `values` - A slice of strings representing the values to be associated with the flag.
fn add_flags(cmd_args: &mut Vec<OsString>, flag: &str, values: &[String]) {
    for value in values {
        if !value.is_empty() {
            cmd_args.push(flag.into());
            cmd_args.push(value.into());
        }
    }
}

/// Builds mmdebstrap command-line arguments from the given profile configuration.
///
/// This function builds a vector of command-line arguments that will be passed to the mmdebstrap
/// utility for creating Debian-based system images. It processes various configuration parameters
/// from the provided profile and formats them according to mmdebstrap's requirements.
///
/// # Arguments
/// * `profile` - A reference to a `Profile` struct containing the configuration for mmdebstrap.
///
/// # Returns
/// A `Vec<OsString>` containing all the command-line arguments to be passed to mmdebstrap.
///
/// # Note
/// The function logs the complete command that would be executed at the debug level
/// for troubleshooting purposes.
///
/// # Example
/// ```
/// use camino::Utf8PathBuf;
/// use rsdebstrap::config::{Format, Mmdebstrap, Mode, Profile, Variant};
///
/// let profile = Profile {
///     dir: Utf8PathBuf::from("/tmp"),
///     mmdebstrap: Mmdebstrap {
///         suite: "bookworm".to_string(),
///         target: "output.tar".to_string(),
///         mode: Mode::Auto,
///         format: Format::Auto,
///         variant: Variant::Debootstrap,
///         architectures: vec!["amd64".to_string()],
///         components: vec!["main".to_string()],
///         include: vec!["base-files".to_string()],
///         keyring: vec![],
///         aptopt: vec![],
///         dpkgopt: vec![],
///         setup_hook: vec![],
///         extract_hook: vec![],
///         essential_hook: vec![],
///         customize_hook: vec![],
///     },
/// };
///
/// let args = rsdebstrap::builder::build_mmdebstrap_args(&profile);
/// // args now contains all necessary command-line arguments for mmdebstrap
/// ```
#[tracing::instrument(skip(profile))]
pub fn build_mmdebstrap_args(profile: &Profile) -> Vec<OsString> {
    let mut cmd_args = Vec::<OsString>::new();

    add_flag(&mut cmd_args, "--mode", &profile.mmdebstrap.mode.to_string());
    add_flag(&mut cmd_args, "--format", &profile.mmdebstrap.format.to_string());
    add_flag(&mut cmd_args, "--variant", &profile.mmdebstrap.variant.to_string());

    add_flag(&mut cmd_args, "--architectures", &profile.mmdebstrap.architectures.join(","));
    add_flag(&mut cmd_args, "--components", &profile.mmdebstrap.components.join(","));
    add_flag(&mut cmd_args, "--include", &profile.mmdebstrap.include.join(","));

    add_flags(&mut cmd_args, "--keyring", &profile.mmdebstrap.keyring);
    add_flags(&mut cmd_args, "--aptopt", &profile.mmdebstrap.aptopt);
    add_flags(&mut cmd_args, "--dpkgopt", &profile.mmdebstrap.dpkgopt);

    add_flags(&mut cmd_args, "--setup-hook", &profile.mmdebstrap.setup_hook);
    add_flags(&mut cmd_args, "--extract-hook", &profile.mmdebstrap.extract_hook);
    add_flags(&mut cmd_args, "--essential-hook", &profile.mmdebstrap.essential_hook);
    add_flags(&mut cmd_args, "--customize-hook", &profile.mmdebstrap.customize_hook);

    cmd_args.push(profile.mmdebstrap.suite.clone().into());

    cmd_args.push(
        profile
            .dir
            .join(&profile.mmdebstrap.target)
            .into_os_string(),
    );

    debug!(
        "mmdebstrap would run: mmdebstrap {}",
        cmd_args
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );

    cmd_args
}
