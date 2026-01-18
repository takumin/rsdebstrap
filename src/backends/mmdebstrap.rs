//! mmdebstrap backend implementation.

use super::{BootstrapBackend, CommandArgsBuilder, FlagValueStyle, RootfsOutput};
use anyhow::Result;
use camino::Utf8Path;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fmt;
use tracing::debug;

/// Known archive file extensions that indicate non-directory output formats.
/// Used to detect archive targets when format is set to Auto.
const KNOWN_ARCHIVE_EXTENSIONS: &[&str] =
    &["tar", "gz", "bz2", "xz", "zst", "squashfs", "ext2", "img"];

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

impl BootstrapBackend for MmdebstrapConfig {
    fn command_name(&self) -> &str {
        "mmdebstrap"
    }

    #[tracing::instrument(skip(self, output_dir))]
    fn build_args(&self, output_dir: &Utf8Path) -> Result<Vec<OsString>> {
        let mut builder = CommandArgsBuilder::new();

        // Only add flags if they differ from defaults
        if self.mode != Mode::Auto {
            builder.push_flag_value("--mode", &self.mode.to_string(), FlagValueStyle::Separate);
        }
        if self.format != Format::Auto {
            builder.push_flag_value("--format", &self.format.to_string(), FlagValueStyle::Separate);
        }
        if self.variant != Variant::Debootstrap {
            builder.push_flag_value(
                "--variant",
                &self.variant.to_string(),
                FlagValueStyle::Separate,
            );
        }

        builder.push_flag_value(
            "--architectures",
            &self.architectures.join(","),
            FlagValueStyle::Separate,
        );
        builder.push_flag_value(
            "--components",
            &self.components.join(","),
            FlagValueStyle::Separate,
        );
        builder.push_flag_value("--include", &self.include.join(","), FlagValueStyle::Separate);

        builder.push_flag_values("--keyring", &self.keyring, FlagValueStyle::Separate);
        builder.push_flag_values("--aptopt", &self.aptopt, FlagValueStyle::Separate);
        builder.push_flag_values("--dpkgopt", &self.dpkgopt, FlagValueStyle::Separate);

        builder.push_flag_values("--setup-hook", &self.setup_hook, FlagValueStyle::Separate);
        builder.push_flag_values("--extract-hook", &self.extract_hook, FlagValueStyle::Separate);
        builder.push_flag_values(
            "--essential-hook",
            &self.essential_hook,
            FlagValueStyle::Separate,
        );
        builder.push_flag_values(
            "--customize-hook",
            &self.customize_hook,
            FlagValueStyle::Separate,
        );

        builder.push_arg(self.suite.clone());

        builder.push_arg(output_dir.join(&self.target).into_os_string());

        let mut cmd_args = builder.into_args();

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

    fn rootfs_output(&self, output_dir: &Utf8Path) -> Result<RootfsOutput> {
        let target_path = output_dir.join(&self.target);

        match &self.format {
            Format::Directory => Ok(RootfsOutput::Directory(target_path)),
            Format::Auto => {
                let archive_ext = target_path.extension().filter(|ext| {
                    KNOWN_ARCHIVE_EXTENSIONS
                        .iter()
                        .any(|known_ext| known_ext.eq_ignore_ascii_case(ext))
                });

                if let Some(ext) = archive_ext {
                    Ok(RootfsOutput::NonDirectory {
                        reason: format!("archive format detected based on extension: {}", ext),
                    })
                } else {
                    Ok(RootfsOutput::Directory(target_path))
                }
            }
            unsupported_format => Ok(RootfsOutput::NonDirectory {
                reason: format!("non-directory format specified: {}", unsupported_format),
            }),
        }
    }
}
