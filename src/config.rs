//! Configuration module for rsdebstrap.
//!
//! This module provides data structures and functions for configuring
//! the Debian bootstrapping process. It includes structures to define
//! bootstrapping profiles for different bootstrap tools (mmdebstrap, debootstrap, etc.).
//!
//! The configuration is typically loaded from YAML files using the
//! `load_profile` function.

use std::fs::File;
use std::io::BufReader;
use std::sync::LazyLock;

use camino::{Utf8Path, Utf8PathBuf};
use regex::Regex;
use serde::Deserialize;
use tracing::debug;

use crate::bootstrap::{
    BootstrapBackend, RootfsOutput, debootstrap::DebootstrapConfig, mmdebstrap::MmdebstrapConfig,
};
use crate::error::RsdebstrapError;
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
    /// Main provisioning tasks (optional)
    #[serde(default)]
    pub provisioners: Vec<TaskDefinition>,
    /// Post-processors to run after provisioning (optional)
    #[serde(default)]
    pub post_processors: Vec<TaskDefinition>,
}

impl Profile {
    /// Creates a `Pipeline` from this profile's task phases.
    pub fn pipeline(&self) -> Pipeline<'_> {
        Pipeline::new(&self.pre_processors, &self.provisioners, &self.post_processors)
    }

    /// Validate configuration semantics beyond basic deserialization.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        if self.dir.exists() && !self.dir.is_dir() {
            return Err(RsdebstrapError::Validation(format!(
                "dir must be a directory: {}",
                self.dir
            )));
        }

        // Validate all tasks across phases
        let pipeline = self.pipeline();
        pipeline.validate()?;

        // Validate tasks are compatible with bootstrap output format.
        // rootfs_output() returns anyhow::Result, so we attempt to downcast to
        // RsdebstrapError to preserve the original variant. If downcast fails
        // (e.g., a non-RsdebstrapError from a backend), we fall back to Validation.
        if !pipeline.is_empty() {
            let backend = self.bootstrap.as_backend();
            let output = backend.rootfs_output(&self.dir).map_err(|e| {
                match e.downcast::<RsdebstrapError>() {
                    Ok(typed_err) => typed_err,
                    Err(e) => RsdebstrapError::Validation(format!("{:#}", e)),
                }
            })?;
            if let RootfsOutput::NonDirectory { reason } = output {
                return Err(RsdebstrapError::Validation(format!(
                    "pipeline tasks require directory output but got: {}. \
                    Use backend-specific hooks or change format to directory.",
                    reason
                )));
            }
        }

        Ok(())
    }
}

fn resolve_profile_paths(profile: &mut Profile, profile_dir: &Utf8Path) {
    if profile.dir.is_relative() {
        profile.dir = profile_dir.join(&profile.dir);
    }

    for task in profile
        .pre_processors
        .iter_mut()
        .chain(profile.provisioners.iter_mut())
        .chain(profile.post_processors.iter_mut())
    {
        task.resolve_paths(profile_dir);
    }
}

/// Loads a bootstrap profile from a YAML file.
///
/// # Arguments
///
/// * `path` - Path to the YAML profile file
///
/// # Errors
///
/// Returns `RsdebstrapError::Io` if the file cannot be read,
/// `RsdebstrapError::Validation` if the path is a directory,
/// or `RsdebstrapError::Config` if the YAML is invalid or missing required fields.
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
pub fn load_profile(path: &Utf8Path) -> Result<Profile, RsdebstrapError> {
    // Canonicalize the entire path first to resolve all symlinks and get the true absolute path.
    // This ensures relative paths in the profile are resolved relative to the actual file location,
    // not the symlink location.
    let canonical_path = path
        .canonicalize_utf8()
        .map_err(|e| RsdebstrapError::io(path.to_string(), e))?;

    // Check if the path is a directory before attempting to open it.
    // On Linux, File::open succeeds on directories but read fails later.
    if canonical_path.is_dir() {
        return Err(RsdebstrapError::Validation(format!(
            "expected a file, not a directory: {}",
            canonical_path
        )));
    }

    let file = File::open(&canonical_path)
        .map_err(|e| RsdebstrapError::io(canonical_path.to_string(), e))?;
    let reader = BufReader::new(file);
    let mut profile: Profile = serde_yaml::from_reader(reader).map_err(|e| {
        let location = e
            .location()
            .map(|loc| format!(" at line {}, column {}", loc.line(), loc.column()));
        // Remove duplicate "at line X column Y" from serde_yaml's error message
        let msg = e.to_string();
        let clean_msg = YAML_LOCATION_RE.replace(&msg, "").to_string();
        RsdebstrapError::Config(format!(
            "{}: YAML parse error{}: {}",
            canonical_path,
            location.unwrap_or_default(),
            clean_msg
        ))
    })?;

    // While parent() should always return Some for canonical file paths,
    // we handle None for defensive programming
    let profile_dir = canonical_path.parent().ok_or_else(|| {
        RsdebstrapError::Config(format!(
            "could not determine parent directory of profile path: {}",
            canonical_path
        ))
    })?;
    resolve_profile_paths(&mut profile, profile_dir);
    debug!("loaded profile:\n{:#?}", profile);
    Ok(profile)
}
