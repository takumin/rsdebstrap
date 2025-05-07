use anyhow::{Context, Ok, Result};
use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::File;
use std::io::BufReader;

#[derive(Debug, Deserialize)]
pub struct Profile {
    pub dir: Utf8PathBuf,
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

#[derive(Debug, Deserialize)]
pub struct Mmdebstrap {
    pub suite: String,
    pub target: String,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub format: Format,
    #[serde(default)]
    pub variant: Variant,
    #[serde(default)]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub components: Vec<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub keyring: Vec<String>,
    #[serde(default)]
    pub aptopt: Vec<String>,
    #[serde(default)]
    pub dpkgopt: Vec<String>,
    #[serde(default)]
    pub setup_hook: Vec<String>,
    #[serde(default)]
    pub extract_hook: Vec<String>,
    #[serde(default)]
    pub essential_hook: Vec<String>,
    #[serde(default)]
    pub customize_hook: Vec<String>,
}

pub fn load_profile(path: &Utf8Path) -> Result<Profile> {
    let file = File::open(path).with_context(|| format!("failed to load file: {}", path))?;
    let reader = BufReader::new(file);
    let profile: Profile = serde_yaml::from_reader(reader)
        .with_context(|| format!("failed to parse yaml: {}", path))?;
    Ok(profile)
}
