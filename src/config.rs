//! Configuration module for rsdebstrap.
//!
//! This module provides data structures and functions for configuring
//! the Debian bootstrapping process. It includes structures to define
//! bootstrapping profiles, variants, modes, and output formats.
//!
//! The configuration is typically loaded from YAML files using the
//! `load_profile` function.

use anyhow::{Context, Ok, Result};
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use tracing::debug;

/// Represents a bootstrap profile configuration.
///
/// A profile contains the target directory and mmdebstrap configuration
/// details needed to create a Debian-based system.
#[derive(Debug, Deserialize)]
pub struct Profile {
    /// Target directory path for the bootstrap operation
    pub dir: Utf8PathBuf,
    /// Configuration for mmdebstrap
    pub mmdebstrap: Mmdebstrap,
}

/// Variant defines the package selection strategy for Debian bootstrap
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
/// bootstrapping process, including package selection, format, mode,
/// and hook scripts.
#[derive(Debug, Deserialize)]
pub struct Mmdebstrap {
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

impl Mmdebstrap {
    /// Creates a new Mmdebstrap configuration with minimal required fields.
    ///
    /// All optional fields are initialized with their default values.
    ///
    /// # Arguments
    /// * `suite` - Debian suite name (e.g., "bookworm", "sid")
    /// * `target` - Target output path
    ///
    /// # Returns
    /// A new `Mmdebstrap` instance with default values for all optional fields
    ///
    /// # Example
    /// ```
    /// use rsdebstrap::config::Mmdebstrap;
    ///
    /// let config = Mmdebstrap::new("bookworm".to_string(), "rootfs.tar.zst".to_string());
    /// assert_eq!(config.suite, "bookworm");
    /// assert_eq!(config.target, "rootfs.tar.zst");
    /// assert!(config.mirrors.is_empty());
    /// ```
    pub fn new(suite: String, target: String) -> Self {
        Self {
            suite,
            target,
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
}

/// Loads a bootstrap profile from a YAML file.
///
/// # Arguments
///
/// * `path` - Path to the YAML profile file
///
/// # Returns
///
/// * `Result<Profile>` - The loaded profile configuration or an error
///
/// # Examples
///
/// ```no_run
/// use camino::Utf8Path;
/// use rsdebstrap::config;
///
/// let profile = config::load_profile(Utf8Path::new("./examples/debian_bookworm.yml")).unwrap();
/// println!("Profile directory: {}", profile.dir);
/// ```
#[tracing::instrument]
pub fn load_profile(path: &Utf8Path) -> Result<Profile> {
    let file = File::open(path).with_context(|| format!("failed to load file: {}", path))?;
    let reader = BufReader::new(file);
    let profile: Profile = serde_yaml::from_reader(reader)
        .with_context(|| format!("failed to parse yaml: {}", path))?;
    debug!("loaded profile:\n{:#?}", profile);
    Ok(profile)
}
