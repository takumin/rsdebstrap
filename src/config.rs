//! Configuration module for rsdebstrap.
//!
//! This module provides data structures and functions for configuring
//! the Debian bootstrapping process. It includes structures to define
//! bootstrapping profiles for different bootstrap tools (mmdebstrap, debootstrap, etc.).
//!
//! The configuration is typically loaded from YAML files using the
//! `load_profile` function.

use anyhow::{Context, Ok, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use tracing::debug;

use crate::bootstrap::{
    BootstrapBackend, RootfsOutput, debootstrap::DebootstrapConfig, mmdebstrap::MmdebstrapConfig,
};
use crate::isolation::{ChrootProvider, IsolationProvider};
use crate::provisioners::{Provisioner, shell::ShellProvisioner};

/// Bootstrap backend configuration.
///
/// This enum represents the different bootstrap tools that can be used.
/// The `type` field in YAML determines which variant is used.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Bootstrap {
    /// mmdebstrap backend
    Mmdebstrap(MmdebstrapConfig),
    /// debootstrap backend
    Debootstrap(DebootstrapConfig),
}

impl Bootstrap {
    /// Returns a reference to the underlying backend as a trait object.
    ///
    /// This allows calling `BootstrapBackend` methods without matching
    /// on each variant explicitly.
    pub fn as_backend(&self) -> &dyn BootstrapBackend {
        match self {
            Bootstrap::Mmdebstrap(cfg) => cfg,
            Bootstrap::Debootstrap(cfg) => cfg,
        }
    }
}

/// Isolation backend configuration.
///
/// This enum represents the different isolation mechanisms that can be used
/// to execute commands within a rootfs. The `type` field in YAML determines
/// which variant is used. If not specified, defaults to chroot.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IsolationConfig {
    /// chroot isolation (default)
    #[default]
    Chroot,
    // Future: Bwrap(BwrapConfig), Nspawn(NspawnConfig)
}

impl IsolationConfig {
    /// Returns a boxed isolation provider instance.
    ///
    /// This allows calling `IsolationProvider` methods without matching
    /// on each variant explicitly.
    pub fn as_provider(&self) -> Box<dyn IsolationProvider> {
        match self {
            IsolationConfig::Chroot => Box::new(ChrootProvider),
        }
    }
}

/// Represents a bootstrap profile configuration.
///
/// A profile contains the target directory and bootstrap tool configuration
/// details needed to create a Debian-based system.
#[derive(Debug, Deserialize)]
pub struct Profile {
    /// Target directory path for the bootstrap operation
    pub dir: Utf8PathBuf,
    /// Isolation backend for running commands in rootfs (default: chroot)
    #[serde(default)]
    pub isolation: IsolationConfig,
    /// Bootstrap tool configuration
    pub bootstrap: Bootstrap,
    /// Provisioners to run after bootstrap (optional)
    #[serde(default)]
    pub provisioners: Vec<ProvisionerConfig>,
}

impl Profile {
    /// Validate configuration semantics beyond basic deserialization.
    pub fn validate(&self) -> Result<()> {
        if self.dir.exists() && !self.dir.is_dir() {
            bail!("dir must be a directory: {}", self.dir);
        }
        for (index, provisioner) in self.provisioners.iter().enumerate() {
            provisioner
                .validate()
                .with_context(|| format!("provisioner {} validation failed", index + 1))?;
        }

        // Validate provisioners are compatible with bootstrap output format
        if !self.provisioners.is_empty() {
            let backend = self.bootstrap.as_backend();
            if let RootfsOutput::NonDirectory { reason } = backend.rootfs_output(&self.dir)? {
                bail!(
                    "provisioners require directory output but got: {}. \
                    Use backend-specific hooks or change format to directory.",
                    reason
                );
            }
        }

        Ok(())
    }
}

/// Provisioner configuration.
///
/// This enum represents the different provisioner types that can be used.
/// The `type` field in YAML determines which variant is used.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProvisionerConfig {
    /// Shell script provisioner
    Shell(ShellProvisioner),
}

impl ProvisionerConfig {
    /// Returns a reference to the underlying provisioner as a trait object.
    ///
    /// This allows calling `Provisioner` methods without matching
    /// on each variant explicitly.
    pub fn as_provisioner(&self) -> &dyn Provisioner {
        match self {
            ProvisionerConfig::Shell(cfg) => cfg,
        }
    }

    /// Validate provisioner configuration.
    pub fn validate(&self) -> Result<()> {
        match self {
            ProvisionerConfig::Shell(cfg) => cfg.validate(),
        }
    }
}

fn resolve_profile_paths(profile: &mut Profile, profile_dir: &Utf8Path) {
    if profile.dir.is_relative() {
        profile.dir = profile_dir.join(&profile.dir);
    }

    for provisioner in &mut profile.provisioners {
        match provisioner {
            ProvisionerConfig::Shell(shell) => {
                if let Some(script) = shell.script_path_mut()
                    && script.is_relative()
                {
                    let resolved = profile_dir.join(script.as_path());
                    *script = resolved;
                }
            }
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
/// let profile =
///     config::load_profile(Utf8Path::new("./examples/debian_trixie_mmdebstrap.yml")).unwrap();
/// println!("Profile directory: {}", profile.dir);
/// ```
#[tracing::instrument]
pub fn load_profile(path: &Utf8Path) -> Result<Profile> {
    // Canonicalize the entire path first to resolve all symlinks and get the true absolute path.
    // This ensures relative paths in the profile are resolved relative to the actual file location,
    // not the symlink location.
    let canonical_path = path
        .canonicalize_utf8()
        .with_context(|| format!("failed to canonicalize path: {}", path))?;

    let file = File::open(&canonical_path)
        .with_context(|| format!("failed to load file: {}", canonical_path))?;
    let reader = BufReader::new(file);
    let mut profile: Profile = serde_yaml::from_reader(reader)
        .with_context(|| format!("failed to parse yaml: {}", canonical_path))?;

    // While parent() should always return Some for canonical file paths,
    // we handle None for defensive programming
    let profile_dir = canonical_path.parent().with_context(|| {
        format!("could not determine parent directory of profile path: {}", canonical_path)
    })?;
    resolve_profile_paths(&mut profile, profile_dir);
    debug!("loaded profile:\n{:#?}", profile);
    Ok(profile)
}
