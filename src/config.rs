//! Configuration module for rsdebstrap.
//!
//! This module provides data structures and functions for configuring
//! the Debian bootstrapping process. It includes structures to define
//! bootstrapping profiles for different bootstrap tools (mmdebstrap, debootstrap, etc.).
//!
//! The configuration is typically loaded from YAML files using the
//! `load_profile` function.

use std::collections::HashMap;
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
use crate::privilege::{Privilege, PrivilegeDefaults, PrivilegeMethod};
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

    /// Returns a reference to the privilege setting of the bootstrap backend.
    pub fn privilege(&self) -> &Privilege {
        match self {
            Bootstrap::Mmdebstrap(cfg) => &cfg.privilege,
            Bootstrap::Debootstrap(cfg) => &cfg.privilege,
        }
    }

    /// Resolves the privilege setting against profile defaults, replacing
    /// the stored `Privilege` with a fully resolved variant.
    pub fn resolve_privilege(
        &mut self,
        defaults: Option<&PrivilegeDefaults>,
    ) -> Result<(), RsdebstrapError> {
        match self {
            Bootstrap::Mmdebstrap(cfg) => cfg.privilege.resolve_in_place(defaults),
            Bootstrap::Debootstrap(cfg) => cfg.privilege.resolve_in_place(defaults),
        }
    }

    /// Returns the resolved privilege method for the bootstrap backend.
    ///
    /// Should only be called after `resolve_privilege()`.
    pub fn resolved_privilege_method(&self) -> Option<PrivilegeMethod> {
        self.privilege().resolved_method()
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

/// Default settings for mitamae tasks.
///
/// Allows specifying architecture-specific binary paths that apply to all
/// mitamae tasks unless overridden at the task level.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct MitamaeDefaults {
    /// Architecture-specific binary paths (key: "x86_64", "aarch64", etc.)
    #[serde(default)]
    pub binary: HashMap<String, Utf8PathBuf>,
}

/// Default settings that apply across the profile.
///
/// Groups configuration defaults like isolation backend.
/// If omitted in YAML, all fields use their respective defaults.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct Defaults {
    /// Isolation backend for running commands in rootfs (default: chroot)
    #[serde(default)]
    pub isolation: IsolationConfig,
    /// Default settings for mitamae tasks
    #[serde(default)]
    pub mitamae: MitamaeDefaults,
    /// Default privilege escalation settings
    #[serde(default)]
    pub privilege: Option<PrivilegeDefaults>,
}

/// Represents a bootstrap profile configuration.
///
/// A profile contains the target directory and bootstrap tool configuration
/// details needed to create a Debian-based system.
#[derive(Debug, Deserialize)]
pub struct Profile {
    /// Target directory path for the bootstrap operation
    pub dir: Utf8PathBuf,
    /// Default settings (isolation backend, etc.)
    #[serde(default)]
    pub defaults: Defaults,
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
            let output = backend
                .rootfs_output(&self.dir)
                .map_err(RsdebstrapError::from_anyhow_or_validation)?;
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

fn format_yaml_parse_error(err: serde_yaml::Error, file_path: &Utf8Path) -> RsdebstrapError {
    let location = err
        .location()
        .map(|loc| format!(" at line {}, column {}", loc.line(), loc.column()));
    // Remove duplicate "at line X column Y" from serde_yaml's error message
    let msg = err.to_string();
    let clean_msg = YAML_LOCATION_RE.replace(&msg, "").to_string();
    RsdebstrapError::Config(format!(
        "{}: YAML parse error{}: {}",
        file_path,
        location.unwrap_or_default(),
        clean_msg
    ))
}

fn read_profile_file(path: &Utf8Path) -> Result<(BufReader<File>, Utf8PathBuf), RsdebstrapError> {
    // Resolve symlinks so we operate on the real file path.
    let canonical_path = path
        .canonicalize_utf8()
        .map_err(|e| RsdebstrapError::io(path.to_string(), e))?;

    // On Linux, File::open on a directory succeeds silently, so we must
    // check explicitly before attempting to open.
    if canonical_path.is_dir() {
        return Err(RsdebstrapError::Validation(format!(
            "expected a file, not a directory: {}",
            canonical_path
        )));
    }

    let file = File::open(&canonical_path)
        .map_err(|e| RsdebstrapError::io(canonical_path.to_string(), e))?;
    Ok((BufReader::new(file), canonical_path))
}

fn parse_profile_yaml(
    reader: BufReader<File>,
    file_path: &Utf8Path,
) -> Result<Profile, RsdebstrapError> {
    serde_yaml::from_reader(reader).map_err(|e| format_yaml_parse_error(e, file_path))
}

fn apply_defaults_to_tasks(profile: &mut Profile) -> Result<(), RsdebstrapError> {
    let arch = std::env::consts::ARCH;
    let default_binary = profile.defaults.mitamae.binary.get(arch);
    let privilege_defaults = profile.defaults.privilege.as_ref();

    if default_binary.is_none() && !profile.defaults.mitamae.binary.is_empty() {
        let available: Vec<&String> = profile.defaults.mitamae.binary.keys().collect();
        tracing::warn!(
            "defaults.mitamae.binary has entries for {:?} but current architecture is '{}'; \
            no default binary will be applied",
            available,
            arch,
        );
    }

    // Resolve privilege for bootstrap
    profile.bootstrap.resolve_privilege(privilege_defaults)?;

    for task in profile
        .pre_processors
        .iter_mut()
        .chain(profile.provisioners.iter_mut())
        .chain(profile.post_processors.iter_mut())
    {
        if let TaskDefinition::Mitamae(mitamae_task) = task
            && let Some(binary) = default_binary
        {
            mitamae_task.set_binary_if_absent(binary);
        }
        task.resolve_privilege(privilege_defaults)?;
    }

    Ok(())
}

fn resolve_profile_paths(profile: &mut Profile, profile_dir: &Utf8Path) {
    if profile.dir.is_relative() {
        profile.dir = profile_dir.join(&profile.dir);
    }

    // Resolve relative paths in defaults.mitamae.binary
    for binary in profile.defaults.mitamae.binary.values_mut() {
        if binary.is_relative() {
            *binary = profile_dir.join(&*binary);
        }
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
    let (reader, canonical_path) = read_profile_file(path)?;
    let mut profile = parse_profile_yaml(reader, &canonical_path)?;

    let profile_dir = canonical_path.parent().ok_or_else(|| {
        RsdebstrapError::Config(format!(
            "could not determine parent directory of profile path: {}",
            canonical_path
        ))
    })?;
    resolve_profile_paths(&mut profile, profile_dir);
    apply_defaults_to_tasks(&mut profile)?;
    debug!("loaded profile:\n{:#?}", profile);
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // =========================================================================
    // format_yaml_parse_error tests
    // =========================================================================

    /// Generates a serde_yaml::Error by attempting to parse invalid YAML.
    fn make_yaml_error(yaml: &str) -> serde_yaml::Error {
        serde_yaml::from_str::<Profile>(yaml).unwrap_err()
    }

    #[test]
    fn test_format_yaml_parse_error_with_location() {
        // Indentation error produces location info
        let err = make_yaml_error("key: value\n  bad_indent");
        let result = format_yaml_parse_error(err, Utf8Path::new("/test/profile.yml"));
        let msg = result.to_string();
        assert!(msg.contains("/test/profile.yml"), "should contain file path: {}", msg);
        assert!(msg.contains("YAML parse error"), "should contain 'YAML parse error': {}", msg);
        assert!(msg.contains("at line "), "should contain line info: {}", msg);
        assert!(msg.contains("column "), "should contain column info: {}", msg);
    }

    #[test]
    fn test_format_yaml_parse_error_strips_duplicate_location() {
        let err = make_yaml_error("key: value\n  bad_indent");
        let result = format_yaml_parse_error(err, Utf8Path::new("/test/profile.yml"));
        let msg = result.to_string();
        // The "at line X column Y" from serde_yaml's own message should be stripped,
        // leaving only our formatted "at line X, column Y" (with comma)
        let at_count = msg.matches(" at line ").count();
        assert!(
            at_count <= 1,
            "duplicate location should be stripped, found {} occurrences: {}",
            at_count,
            msg
        );
    }

    #[test]
    fn test_format_yaml_parse_error_without_location() {
        // EOF error typically has no location
        let err = make_yaml_error("");
        let result = format_yaml_parse_error(err, Utf8Path::new("/test/empty.yml"));
        let msg = result.to_string();
        assert!(msg.contains("/test/empty.yml"), "should contain file path: {}", msg);
        assert!(msg.contains("YAML parse error"), "should contain 'YAML parse error': {}", msg);
    }

    // =========================================================================
    // read_profile_file tests
    // =========================================================================

    #[test]
    fn test_read_profile_file_success() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            "dir: /tmp\nbootstrap:\n  type: mmdebstrap\n  suite: trixie\n  target: rootfs\n"
        )
        .unwrap();
        tmpfile.flush().unwrap();

        let file_path = Utf8Path::from_path(tmpfile.path()).unwrap();
        let result = read_profile_file(file_path);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.unwrap_err());

        let (_, canonical_path) = result.unwrap();
        assert!(
            canonical_path.is_absolute(),
            "Canonical path should be absolute: {}",
            canonical_path
        );
    }

    #[test]
    fn test_read_profile_file_nonexistent() {
        let result = read_profile_file(Utf8Path::new("/nonexistent/path/file.yml"));
        let err = result.unwrap_err();
        assert!(
            matches!(
                &err,
                RsdebstrapError::Io { source, .. }
                    if source.kind() == std::io::ErrorKind::NotFound
            ),
            "Expected Io error with NotFound, got: {:?}",
            err
        );
    }

    #[test]
    fn test_read_profile_file_directory() {
        let result = read_profile_file(Utf8Path::new("/tmp"));
        let err = result.unwrap_err();
        assert!(
            matches!(&err, RsdebstrapError::Validation(msg) if msg.contains("expected a file")),
            "Expected Validation error about directory, got: {:?}",
            err
        );
    }

    // =========================================================================
    // parse_profile_yaml tests
    // =========================================================================

    #[test]
    fn test_parse_profile_yaml_valid() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            "dir: /tmp/rootfs\nbootstrap:\n  type: mmdebstrap\n  suite: trixie\n  target: rootfs\n"
        )
        .unwrap();
        tmpfile.flush().unwrap();

        let file = File::open(tmpfile.path()).unwrap();
        let reader = BufReader::new(file);
        let file_path = Utf8Path::from_path(tmpfile.path()).unwrap();

        let result = parse_profile_yaml(reader, file_path);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.unwrap_err());

        let profile = result.unwrap();
        assert_eq!(profile.dir, Utf8PathBuf::from("/tmp/rootfs"));
    }

    #[test]
    fn test_parse_profile_yaml_invalid() {
        let mut tmpfile = NamedTempFile::new().unwrap();
        write!(tmpfile, "not: valid\n  yaml_content").unwrap();
        tmpfile.flush().unwrap();

        let file = File::open(tmpfile.path()).unwrap();
        let reader = BufReader::new(file);
        let file_path = Utf8Path::from_path(tmpfile.path()).unwrap();

        let result = parse_profile_yaml(reader, file_path);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, RsdebstrapError::Config(msg) if msg.contains("YAML parse error")),
            "Expected Config error with YAML parse error, got: {:?}",
            err
        );
    }
}
