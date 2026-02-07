//! Configuration module for rsdebstrap.
//!
//! This module provides data structures and functions for configuring
//! the Debian bootstrapping process. It includes structures to define
//! bootstrapping profiles for different bootstrap tools (mmdebstrap, debootstrap, etc.).
//!
//! The configuration is typically loaded from YAML files using the
//! `load_profile` function.

use std::fs::File;
use std::io;
use std::io::BufReader;
use std::sync::LazyLock;

use anyhow::{Context, Ok, Result, bail};
use camino::{Utf8Path, Utf8PathBuf};
use regex::Regex;
use serde::Deserialize;
use tracing::debug;

use crate::bootstrap::{
    BootstrapBackend, RootfsOutput, debootstrap::DebootstrapConfig, mmdebstrap::MmdebstrapConfig,
};
use crate::isolation::{ChrootProvider, IsolationProvider};
use crate::pipeline::Pipeline;
use crate::task::TaskDefinition;

/// Static regex for removing duplicate location info from serde_yaml error messages.
static YAML_LOCATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r" at line \d+ column \d+").unwrap());

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
    /// Pre-processors to run before provisioning (optional)
    #[serde(default)]
    pub pre_processors: Vec<TaskDefinition>,
    /// Provisioners to run after bootstrap (optional)
    #[serde(default)]
    pub provisioners: Vec<TaskDefinition>,
    /// Post-processors to run after provisioning (optional)
    #[serde(default)]
    pub post_processors: Vec<TaskDefinition>,
}

impl Profile {
    /// Validate configuration semantics beyond basic deserialization.
    pub fn validate(&self) -> Result<()> {
        if self.dir.exists() && !self.dir.is_dir() {
            bail!("dir must be a directory: {}", self.dir);
        }

        // Validate all tasks across phases
        let pipeline =
            Pipeline::new(&self.pre_processors, &self.provisioners, &self.post_processors);
        pipeline.validate()?;

        // Validate tasks are compatible with bootstrap output format
        if !pipeline.is_empty() {
            let backend = self.bootstrap.as_backend();
            if let RootfsOutput::NonDirectory { reason } = backend.rootfs_output(&self.dir)? {
                bail!(
                    "pipeline tasks require directory output but got: {}. \
                    Use backend-specific hooks or change format to directory.",
                    reason
                );
            }
        }

        Ok(())
    }
}

fn resolve_profile_paths(profile: &mut Profile, profile_dir: &Utf8Path) {
    if profile.dir.is_relative() {
        profile.dir = profile_dir.join(&profile.dir);
    }

    for task in &mut profile.pre_processors {
        task.resolve_paths(profile_dir);
    }
    for task in &mut profile.provisioners {
        task.resolve_paths(profile_dir);
    }
    for task in &mut profile.post_processors {
        task.resolve_paths(profile_dir);
    }
}

/// Formats an IO error with a descriptive message based on the error kind.
fn io_error_message(err: &io::Error, path: &Utf8Path) -> String {
    match err.kind() {
        io::ErrorKind::NotFound => format!("{}: I/O error: file not found", path),
        io::ErrorKind::PermissionDenied => format!("{}: I/O error: permission denied", path),
        io::ErrorKind::IsADirectory => format!("{}: I/O error: is a directory", path),
        _ => format!("{}: I/O error: {}", path, err),
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
        .map_err(|e| anyhow::anyhow!(io_error_message(&e, path)))?;

    // Check if the path is a directory before attempting to open it.
    // On Linux, File::open succeeds on directories but read fails later.
    if canonical_path.is_dir() {
        bail!("{}: I/O error: is a directory", canonical_path);
    }

    let file = File::open(&canonical_path)
        .map_err(|e| anyhow::anyhow!(io_error_message(&e, &canonical_path)))?;
    let reader = BufReader::new(file);
    let mut profile: Profile = serde_yaml::from_reader(reader).map_err(|e| {
        let location = e
            .location()
            .map(|loc| format!(" at line {}, column {}", loc.line(), loc.column()));
        // Remove duplicate "at line X column Y" from serde_yaml's error message
        let msg = e.to_string();
        let clean_msg = YAML_LOCATION_RE.replace(&msg, "").to_string();
        anyhow::anyhow!(
            "{}: YAML parse error{}: {}",
            canonical_path,
            location.unwrap_or_default(),
            clean_msg
        )
    })?;

    // While parent() should always return Some for canonical file paths,
    // we handle None for defensive programming
    let profile_dir = canonical_path.parent().with_context(|| {
        format!("could not determine parent directory of profile path: {}", canonical_path)
    })?;
    resolve_profile_paths(&mut profile, profile_dir);
    debug!("loaded profile:\n{:#?}", profile);
    Ok(profile)
}
