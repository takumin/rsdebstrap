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

use crate::backends::{
    BootstrapBackend, RootfsOutput, debootstrap::DebootstrapConfig, mmdebstrap::MmdebstrapConfig,
};
use crate::provisioners::{Provisioner, shell::ShellProvisioner};

/// Represents a bootstrap profile configuration.
///
/// A profile contains the target directory and bootstrap tool configuration
/// details needed to create a Debian-based system.
#[derive(Debug, Deserialize)]
pub struct Profile {
    /// Target directory path for the bootstrap operation
    pub dir: Utf8PathBuf,
    /// Bootstrap tool configuration
    pub bootstrap: Bootstrap,
    /// Provisioners to run after bootstrap (optional)
    #[serde(default)]
    pub provisioners: Vec<ProvisionerConfig>,
}

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
            match backend.rootfs_output(&self.dir)? {
                RootfsOutput::Directory(_) => {
                    // This is fine - provisioners can run on directory output
                }
                RootfsOutput::NonDirectory { reason } => {
                    bail!(
                        "provisioners are specified but bootstrap output is not a directory: {}. \
                        Provisioners require a directory-based bootstrap target. \
                        For archive-based targets (tar, squashfs, etc.), \
                        consider using backend-specific hooks instead or change the output format to directory.",
                        reason
                    );
                }
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

fn resolve_provisioner_paths(profile: &mut Profile, profile_dir: &Utf8Path) {
    for provisioner in &mut profile.provisioners {
        match provisioner {
            ProvisionerConfig::Shell(shell) => {
                if let Some(script) = shell.script.as_mut()
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
    let file = File::open(path).with_context(|| format!("failed to load file: {}", path))?;
    let reader = BufReader::new(file);
    let mut profile: Profile = serde_yaml::from_reader(reader)
        .with_context(|| format!("failed to parse yaml: {}", path))?;
    let profile_dir = path.parent().unwrap_or_else(|| Utf8Path::new("."));
    resolve_provisioner_paths(&mut profile, profile_dir);
    debug!("loaded profile:\n{:#?}", profile);
    Ok(profile)
}
