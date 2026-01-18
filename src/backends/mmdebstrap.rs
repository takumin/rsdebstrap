//! mmdebstrap backend implementation.

use super::BootstrapBackend;
use anyhow::Result;
use camino::Utf8Path;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fmt;
use tracing::debug;

/// Variant defines the package selection strategy for mmdebstrap
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Variant {
    /// The `required` set plus all packages with `Priority:important` (default)
    #[serde(alias = "")]
    #[default]
    Debootstrap,
    /// Installs nothing by default (not even `Essential:yes` packages)
    /// This variant is used for minimal setups where no preselected packages are required
    Extract,
    /// Installs nothing by default (not even `Essential:yes` packages)
    /// This variant allows for fully custom package selection strategies defined by the user
    Custom,
    /// `Essential:yes` packages
    Essential,
    /// The `essential` set plus `apt`
    Apt,
    /// The `essential` set plus `apt` and `build-essential`
    Buildd,
    /// The `essential` set plus all packages with `Priority:required`
    Required,
    /// The `essential` set plus all packages with `Priority:required`
    Minbase,
    /// The `required` set plus all packages with `Priority:important`
    Important,
    /// The `important` set plus all packages with `Priority:standard`
    Standard,
}

impl fmt::Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Variant::Debootstrap => write!(f, "debootstrap"),
            Variant::Extract => write!(f, "extract"),
            Variant::Custom => write!(f, "custom"),
            Variant::Essential => write!(f, "essential"),
            Variant::Apt => write!(f, "apt"),
            Variant::Buildd => write!(f, "buildd"),
            Variant::Required => write!(f, "required"),
            Variant::Minbase => write!(f, "minbase"),
            Variant::Important => write!(f, "important"),
            Variant::Standard => write!(f, "standard"),
        }
    }
}

/// Mode for mmdebstrap operation
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Auto detect best mode (default)
    #[serde(alias = "")]
    #[default]
    Auto,
    /// Sudo mode
    Sudo,
    /// Root mode
    Root,
    /// Unshare mode
    Unshare,
    /// User-mode using fakeroot
    Fakeroot,
    /// Fakechroot mode
    Fakechroot,
    /// Chrootless mode
    Chrootless,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Auto => write!(f, "auto"),
            Mode::Sudo => write!(f, "sudo"),
            Mode::Root => write!(f, "root"),
            Mode::Unshare => write!(f, "unshare"),
            Mode::Fakeroot => write!(f, "fakeroot"),
            Mode::Fakechroot => write!(f, "fakechroot"),
            Mode::Chrootless => write!(f, "chrootless"),
        }
    }
}

/// Format for the target output
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Auto detect based on file extension (default)
    #[serde(alias = "")]
    #[default]
    Auto,
    /// Directory format
    Directory,
    /// Tarball
    Tar,
    /// Compressed tarball (xz)
    TarXz,
    /// Compressed tarball (gz)
    TarGz,
    /// Compressed tarball (zst)
    TarZst,
    /// Squashfs filesystem
    Squashfs,
    /// Ext2 filesystem
    Ext2,
    /// Null
    Null,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::Auto => write!(f, "auto"),
            Format::Directory => write!(f, "directory"),
            Format::Tar => write!(f, "tar"),
            Format::TarXz => write!(f, "tar.xz"),
            Format::TarGz => write!(f, "tar.gz"),
            Format::TarZst => write!(f, "tar.zst"),
            Format::Squashfs => write!(f, "squashfs"),
            Format::Ext2 => write!(f, "ext2"),
            Format::Null => write!(f, "null"),
        }
    }
}

/// Configuration for mmdebstrap operations.
///
/// This structure contains all settings needed to customize the Debian
/// bootstrapping process using mmdebstrap, including package selection,
/// format, mode, and hook scripts.
#[derive(Debug, Deserialize)]
pub struct MmdebstrapConfig {
    /// Debian suite name (e.g., "bookworm", "sid")
    pub suite: String,
    /// Target output path
    pub target: String,
    /// Operation mode (defaults to Auto)
    #[serde(default)]
    pub mode: Mode,
    /// Output format (defaults to Auto)
    #[serde(default)]
    pub format: Format,
    /// Package selection variant (defaults to Debootstrap)
    #[serde(default)]
    pub variant: Variant,
    /// Target architectures
    #[serde(default)]
    pub architectures: Vec<String>,
    /// Repository components to enable (e.g., "main", "contrib", "non-free")
    #[serde(default)]
    pub components: Vec<String>,
    /// Additional packages to include
    #[serde(default)]
    pub include: Vec<String>,
    /// Keyring paths for repository verification
    #[serde(default)]
    pub keyring: Vec<String>,
    /// Additional APT options
    #[serde(default)]
    pub aptopt: Vec<String>,
    /// Additional dpkg options
    #[serde(default)]
    pub dpkgopt: Vec<String>,
    /// Setup hook scripts
    #[serde(default)]
    pub setup_hook: Vec<String>,
    /// Extract hook scripts
    #[serde(default)]
    pub extract_hook: Vec<String>,
    /// Essential hook scripts
    #[serde(default)]
    pub essential_hook: Vec<String>,
    /// Customize hook scripts
    #[serde(default)]
    pub customize_hook: Vec<String>,
    /// APT mirror URLs to use as package sources
    #[serde(default)]
    pub mirrors: Vec<String>,
}

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

impl BootstrapBackend for MmdebstrapConfig {
    fn command_name(&self) -> &str {
        "mmdebstrap"
    }

    #[tracing::instrument(skip(self, output_dir))]
    fn build_args(&self, output_dir: &Utf8Path) -> Result<Vec<OsString>> {
        let mut cmd_args = Vec::<OsString>::new();

        add_flag(&mut cmd_args, "--mode", &self.mode.to_string());
        add_flag(&mut cmd_args, "--format", &self.format.to_string());
        add_flag(&mut cmd_args, "--variant", &self.variant.to_string());

        add_flag(&mut cmd_args, "--architectures", &self.architectures.join(","));
        add_flag(&mut cmd_args, "--components", &self.components.join(","));
        add_flag(&mut cmd_args, "--include", &self.include.join(","));

        add_flags(&mut cmd_args, "--keyring", &self.keyring);
        add_flags(&mut cmd_args, "--aptopt", &self.aptopt);
        add_flags(&mut cmd_args, "--dpkgopt", &self.dpkgopt);

        add_flags(&mut cmd_args, "--setup-hook", &self.setup_hook);
        add_flags(&mut cmd_args, "--extract-hook", &self.extract_hook);
        add_flags(&mut cmd_args, "--essential-hook", &self.essential_hook);
        add_flags(&mut cmd_args, "--customize-hook", &self.customize_hook);

        cmd_args.push(self.suite.clone().into());

        cmd_args.push(output_dir.join(&self.target).into_os_string());

        // Add mirrors as positional arguments after suite and target
        cmd_args.extend(
            self.mirrors
                .iter()
                .filter(|m| !m.trim().is_empty())
                .map(|m| m.into()),
        );

        debug!(
            "mmdebstrap would run: mmdebstrap {}",
            cmd_args
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );

        Ok(cmd_args)
    }
}
