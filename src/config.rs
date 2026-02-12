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
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::bootstrap::{
    BootstrapBackend, RootfsOutput, debootstrap::DebootstrapConfig, mmdebstrap::MmdebstrapConfig,
};
use crate::error::RsdebstrapError;
use crate::executor::CommandSpec;
use crate::isolation::{ChrootProvider, IsolationProvider};
use crate::pipeline::Pipeline;
use crate::privilege::{Privilege, PrivilegeDefaults, PrivilegeMethod};
use crate::task::TaskDefinition;

/// Static regex for removing duplicate location info from serde_yaml error messages.
static YAML_LOCATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r" at line \d+ column \d+").unwrap());

/// Known pseudo-filesystem source names.
///
/// These are used to determine the correct `mount -t` type argument.
const PSEUDO_FS_TYPES: &[&str] = &["proc", "sysfs", "devpts", "devtmpfs", "tmpfs"];

/// Mount preset defining a predefined set of mount entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MountPreset {
    /// Recommended mount set for typical Debian rootfs operations.
    Recommends,
}

impl MountPreset {
    /// Expands the preset into a list of mount entries.
    pub fn to_entries(&self) -> Vec<MountEntry> {
        match self {
            Self::Recommends => vec![
                MountEntry {
                    source: "proc".to_string(),
                    target: "/proc".into(),
                    options: vec![],
                },
                MountEntry {
                    source: "sysfs".to_string(),
                    target: "/sys".into(),
                    options: vec![],
                },
                MountEntry {
                    source: "devtmpfs".to_string(),
                    target: "/dev".into(),
                    options: vec![],
                },
                MountEntry {
                    source: "devpts".to_string(),
                    target: "/dev/pts".into(),
                    options: vec!["gid=5".to_string(), "mode=620".to_string()],
                },
                MountEntry {
                    source: "tmpfs".to_string(),
                    target: "/tmp".into(),
                    options: vec![],
                },
                MountEntry {
                    source: "tmpfs".to_string(),
                    target: "/run".into(),
                    options: vec!["mode=755".to_string()],
                },
            ],
        }
    }
}

/// A single mount entry specifying what to mount into the rootfs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountEntry {
    /// Device name or path (e.g., "proc", "sysfs", "/dev").
    pub source: String,
    /// Mount point inside the rootfs (absolute path).
    pub target: Utf8PathBuf,
    /// Mount options (e.g., "bind", "nosuid"). Joined with "," for `-o`.
    #[serde(default)]
    pub options: Vec<String>,
}

impl MountEntry {
    /// Returns true if the source is a known pseudo-filesystem.
    pub fn is_pseudo_fs(&self) -> bool {
        PSEUDO_FS_TYPES.contains(&self.source.as_str())
    }

    /// Returns true if this is a bind mount.
    pub fn is_bind_mount(&self) -> bool {
        self.options.iter().any(|o| o == "bind")
    }

    /// Builds a `CommandSpec` for the `mount` command.
    ///
    /// For pseudo-filesystems, generates: `mount -t <source> [-o opts] <source> <rootfs>/<target>`
    /// For others: `mount [-o opts] <source> <rootfs>/<target>`
    pub fn build_mount_spec(
        &self,
        rootfs: &Utf8Path,
        privilege: Option<PrivilegeMethod>,
    ) -> CommandSpec {
        let abs_target = rootfs.join(self.target.strip_prefix("/").unwrap_or(&self.target));
        let mut args = Vec::new();

        if self.is_pseudo_fs() {
            args.push("-t".to_string());
            args.push(self.source.clone());
        }

        if !self.options.is_empty() {
            args.push("-o".to_string());
            args.push(self.options.join(","));
        }

        args.push(self.source.clone());
        args.push(abs_target.to_string());

        CommandSpec::new("mount", args).with_privilege(privilege)
    }

    /// Builds a `CommandSpec` for the `mount` command using a pre-validated absolute target path.
    ///
    /// Unlike [`build_mount_spec()`](Self::build_mount_spec), this method accepts
    /// an already-validated absolute path (e.g., from
    /// [`safe_create_mount_point()`](crate::isolation::mount::safe_create_mount_point))
    /// instead of computing it from rootfs + target.
    pub fn build_mount_spec_with_path(
        &self,
        abs_target: &Utf8Path,
        privilege: Option<PrivilegeMethod>,
    ) -> CommandSpec {
        let mut args = Vec::new();

        if self.is_pseudo_fs() {
            args.push("-t".to_string());
            args.push(self.source.clone());
        }

        if !self.options.is_empty() {
            args.push("-o".to_string());
            args.push(self.options.join(","));
        }

        args.push(self.source.clone());
        args.push(abs_target.to_string());

        CommandSpec::new("mount", args).with_privilege(privilege)
    }

    /// Builds a `CommandSpec` for the `umount` command.
    pub fn build_umount_spec(
        &self,
        rootfs: &Utf8Path,
        privilege: Option<PrivilegeMethod>,
    ) -> CommandSpec {
        let abs_target = rootfs.join(self.target.strip_prefix("/").unwrap_or(&self.target));
        CommandSpec::new("umount", vec![abs_target.to_string()]).with_privilege(privilege)
    }

    /// Validates this mount entry's format: source must not be empty, target must
    /// be an absolute path (not `/`) without `..` components, pseudo-filesystem
    /// and bind mount are mutually exclusive, and bind/regular mount sources must
    /// be absolute paths.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        if self.source.trim().is_empty() {
            return Err(RsdebstrapError::Validation("mount source must not be empty".to_string()));
        }

        if self.target.as_str() == "/" {
            return Err(RsdebstrapError::Validation(
                "mount target '/' is not allowed (would mount over rootfs itself)".to_string(),
            ));
        }

        if self.is_pseudo_fs() && self.is_bind_mount() {
            return Err(RsdebstrapError::Validation(format!(
                "mount entry for '{}' cannot be both a pseudo-filesystem and a bind mount",
                self.source
            )));
        }

        if !self.target.starts_with("/") {
            return Err(RsdebstrapError::Validation(format!(
                "mount target '{}' must be an absolute path",
                self.target
            )));
        }

        crate::task::validate_no_parent_dirs(&self.target, "mount target")?;

        if self.is_bind_mount() {
            let source_path = Utf8Path::new(&self.source);
            if !source_path.starts_with("/") {
                return Err(RsdebstrapError::Validation(format!(
                    "bind mount source '{}' must be an absolute path",
                    self.source
                )));
            }
            crate::task::validate_no_parent_dirs(source_path, "bind mount source")?;
        } else if !self.is_pseudo_fs() {
            let source_path = Utf8Path::new(&self.source);
            if !source_path.starts_with("/") {
                return Err(RsdebstrapError::Validation(format!(
                    "mount source '{}' is not a recognized pseudo-filesystem and must be \
                    an absolute path (known pseudo-filesystems: {})",
                    self.source,
                    PSEUDO_FS_TYPES.join(", ")
                )));
            }
            crate::task::validate_no_parent_dirs(source_path, "mount source")?;
        }

        Ok(())
    }
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
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IsolationConfig {
    /// chroot isolation (default)
    Chroot {
        /// Optional preset for predefined mount sets.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preset: Option<MountPreset>,
        /// Custom mount entries.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        mounts: Vec<MountEntry>,
    },
    // Future: Bwrap(BwrapConfig), Nspawn(NspawnConfig)
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self::Chroot {
            preset: None,
            mounts: vec![],
        }
    }
}

impl IsolationConfig {
    /// Creates a default chroot config without preset or mounts.
    pub fn chroot() -> Self {
        Self::default()
    }

    /// Returns the resolved list of mount entries.
    ///
    /// If a preset is set, expands the preset entries first. Custom mounts
    /// with the same target as a preset entry replace the preset entry
    /// at its original position, preserving mount order (parent before child).
    /// Non-overlapping custom mounts are appended after preset entries.
    pub fn resolved_mounts(&self) -> Vec<MountEntry> {
        match self {
            Self::Chroot { preset, mounts } => {
                let preset_entries = preset.as_ref().map(|p| p.to_entries()).unwrap_or_default();

                if mounts.is_empty() {
                    return preset_entries;
                }
                if preset_entries.is_empty() {
                    return mounts.clone();
                }

                // Build lookup from target path to custom mount entry
                let custom_by_target: std::collections::HashMap<&Utf8Path, &MountEntry> =
                    mounts.iter().map(|m| (m.target.as_path(), m)).collect();

                let mut used_targets = std::collections::HashSet::new();

                // Replace preset entries in-place where custom overrides exist
                let mut result: Vec<MountEntry> = preset_entries
                    .iter()
                    .map(|e| {
                        if let Some(custom) = custom_by_target.get(e.target.as_path()) {
                            used_targets.insert(e.target.as_path());
                            (*custom).clone()
                        } else {
                            e.clone()
                        }
                    })
                    .collect();

                // Append custom mounts that don't override any preset entry
                for m in mounts {
                    if !used_targets.contains(m.target.as_path()) {
                        result.push(m.clone());
                    }
                }

                result
            }
        }
    }

    /// Returns true if this config has any mount entries (preset or custom).
    pub fn has_mounts(&self) -> bool {
        match self {
            Self::Chroot { preset, mounts } => preset.is_some() || !mounts.is_empty(),
        }
    }

    /// Returns a boxed isolation provider instance.
    ///
    /// This allows calling `IsolationProvider` methods without matching
    /// on each variant explicitly.
    pub fn as_provider(&self) -> Box<dyn IsolationProvider> {
        match self {
            IsolationConfig::Chroot { .. } => Box::new(ChrootProvider),
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

        // Validate mounts configuration
        self.validate_mounts()?;

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

    /// Validates mount-related configuration.
    fn validate_mounts(&self) -> Result<(), RsdebstrapError> {
        let resolved_mounts = self.defaults.isolation.resolved_mounts();

        if resolved_mounts.is_empty() {
            return Ok(());
        }

        // mounts require privilege to be configured
        if self.defaults.privilege.is_none() {
            return Err(RsdebstrapError::Validation(
                "defaults.privilege must be configured when mounts are specified \
                (mount/umount require privilege escalation)"
                    .to_string(),
            ));
        }

        // Validate mount/umount commands exist in PATH
        validate_command_in_path("mount", "mount command")?;
        validate_command_in_path("umount", "umount command")?;

        // Validate each mount entry
        for entry in &resolved_mounts {
            entry.validate()?;

            // Validate bind mount source exists on host
            if entry.is_bind_mount() {
                let source_path = Utf8Path::new(&entry.source);
                if !source_path.exists() {
                    return Err(RsdebstrapError::Validation(format!(
                        "bind mount source '{}' does not exist on host",
                        entry.source
                    )));
                }
            }
        }

        // Validate mount order: parent directories must come before children
        validate_mount_order(&resolved_mounts)?;

        Ok(())
    }
}

/// Validates that a command exists in PATH.
fn validate_command_in_path(command: &str, label: &str) -> Result<(), RsdebstrapError> {
    if which::which(command).is_err() {
        return Err(RsdebstrapError::command_not_found(command, label));
    }
    Ok(())
}

/// Validates that mount entries are in correct order (parent before child).
fn validate_mount_order(mounts: &[MountEntry]) -> Result<(), RsdebstrapError> {
    for (i, entry) in mounts.iter().enumerate() {
        for earlier in &mounts[..i] {
            // If this entry's target is a parent of an earlier entry's target,
            // then this entry should have come first
            if earlier.target.starts_with(&entry.target) && earlier.target != entry.target {
                return Err(RsdebstrapError::Validation(format!(
                    "mount order error: '{}' must be mounted before '{}' \
                    (parent directories must come before children)",
                    entry.target, earlier.target
                )));
            }
        }
    }
    Ok(())
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

/// Validates that task-level isolation configs do not specify preset or mounts.
///
/// Must be called before `resolve_isolation()` so we can distinguish explicit
/// task-level config from inherited defaults.
fn validate_task_isolation_no_mounts(profile: &Profile) -> Result<(), RsdebstrapError> {
    use crate::isolation::TaskIsolation;

    for (phase_name, tasks) in [
        ("pre-processor", profile.pre_processors.as_slice()),
        ("provisioner", profile.provisioners.as_slice()),
        ("post-processor", profile.post_processors.as_slice()),
    ] {
        for (index, task) in tasks.iter().enumerate() {
            if let TaskIsolation::Config(config) = task.task_isolation()
                && config.has_mounts()
            {
                return Err(RsdebstrapError::Validation(format!(
                    "{} {} has preset or mounts in task-level isolation, \
                    which is not supported. Mounts must be configured at \
                    the profile level (defaults.isolation)",
                    phase_name,
                    index + 1,
                )));
            }
        }
    }
    Ok(())
}

fn apply_defaults_to_tasks(profile: &mut Profile) -> Result<(), RsdebstrapError> {
    let arch = std::env::consts::ARCH;
    let default_binary = profile.defaults.mitamae.binary.get(arch);
    let privilege_defaults = profile.defaults.privilege.as_ref();
    let isolation_defaults = profile.defaults.isolation.clone();

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

    // Validate task-level isolation does not specify preset/mounts (before resolution)
    validate_task_isolation_no_mounts(profile)?;

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
        task.resolve_isolation(&isolation_defaults);
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

    // =========================================================================
    // MountEntry tests
    // =========================================================================

    #[test]
    fn test_mount_entry_is_pseudo_fs() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        };
        assert!(entry.is_pseudo_fs());

        let entry = MountEntry {
            source: "/dev".to_string(),
            target: "/dev".into(),
            options: vec!["bind".to_string()],
        };
        assert!(!entry.is_pseudo_fs());
    }

    #[test]
    fn test_mount_entry_is_bind_mount() {
        let entry = MountEntry {
            source: "/dev".to_string(),
            target: "/dev".into(),
            options: vec!["bind".to_string()],
        };
        assert!(entry.is_bind_mount());

        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        };
        assert!(!entry.is_bind_mount());
    }

    #[test]
    fn test_mount_entry_build_mount_spec_pseudo_fs() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        };
        let spec = entry.build_mount_spec(Utf8Path::new("/rootfs"), None);
        assert_eq!(spec.command, "mount");
        assert_eq!(spec.args, vec!["-t", "proc", "proc", "/rootfs/proc"]);
    }

    #[test]
    fn test_mount_entry_build_mount_spec_pseudo_fs_with_options() {
        let entry = MountEntry {
            source: "devpts".to_string(),
            target: "/dev/pts".into(),
            options: vec!["gid=5".to_string(), "mode=620".to_string()],
        };
        let spec = entry.build_mount_spec(Utf8Path::new("/rootfs"), None);
        assert_eq!(spec.command, "mount");
        assert_eq!(
            spec.args,
            vec![
                "-t",
                "devpts",
                "-o",
                "gid=5,mode=620",
                "devpts",
                "/rootfs/dev/pts"
            ]
        );
    }

    #[test]
    fn test_mount_entry_build_mount_spec_bind() {
        let entry = MountEntry {
            source: "/dev".to_string(),
            target: "/dev".into(),
            options: vec!["bind".to_string()],
        };
        let spec = entry.build_mount_spec(Utf8Path::new("/rootfs"), None);
        assert_eq!(spec.command, "mount");
        assert_eq!(spec.args, vec!["-o", "bind", "/dev", "/rootfs/dev"]);
    }

    #[test]
    fn test_mount_entry_build_umount_spec() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        };
        let spec = entry.build_umount_spec(Utf8Path::new("/rootfs"), None);
        assert_eq!(spec.command, "umount");
        assert_eq!(spec.args, vec!["/rootfs/proc"]);
    }

    #[test]
    fn test_mount_entry_build_mount_spec_with_privilege() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        };
        let spec = entry.build_mount_spec(Utf8Path::new("/rootfs"), Some(PrivilegeMethod::Sudo));
        assert_eq!(spec.privilege, Some(PrivilegeMethod::Sudo));
    }

    #[test]
    fn test_mount_entry_validate_valid() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        };
        assert!(entry.validate().is_ok());
    }

    #[test]
    fn test_mount_entry_validate_rejects_relative_target() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "proc".into(),
            options: vec![],
        };
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("absolute path"));
    }

    #[test]
    fn test_mount_entry_validate_rejects_target_with_dotdot() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc/../etc".into(),
            options: vec![],
        };
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains(".."));
    }

    #[test]
    fn test_mount_entry_validate_bind_rejects_relative_source() {
        let entry = MountEntry {
            source: "dev".to_string(),
            target: "/dev".into(),
            options: vec!["bind".to_string()],
        };
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("absolute path"));
    }

    #[test]
    fn test_mount_entry_validate_bind_rejects_source_with_dotdot() {
        let entry = MountEntry {
            source: "/dev/../etc".to_string(),
            target: "/dev".into(),
            options: vec!["bind".to_string()],
        };
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains(".."));
    }

    #[test]
    fn test_mount_entry_serialize_deserialize() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec!["nosuid".to_string()],
        };
        let yaml = serde_yaml::to_string(&entry).unwrap();
        let deserialized: MountEntry = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_mount_entry_deserialize_without_options() {
        let yaml = "source: proc\ntarget: /proc\n";
        let entry: MountEntry = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(entry.source, "proc");
        assert_eq!(entry.target, Utf8PathBuf::from("/proc"));
        assert!(entry.options.is_empty());
    }

    // =========================================================================
    // MountPreset tests
    // =========================================================================

    #[test]
    fn test_mount_preset_recommends_has_expected_entries() {
        let entries = MountPreset::Recommends.to_entries();
        assert_eq!(entries.len(), 6);

        let targets: Vec<&str> = entries.iter().map(|e| e.target.as_str()).collect();
        assert!(targets.contains(&"/proc"));
        assert!(targets.contains(&"/sys"));
        assert!(targets.contains(&"/dev"));
        assert!(targets.contains(&"/dev/pts"));
        assert!(targets.contains(&"/tmp"));
        assert!(targets.contains(&"/run"));
    }

    #[test]
    fn test_mount_preset_deserialize() {
        let preset: MountPreset = serde_yaml::from_str("recommends").unwrap();
        assert_eq!(preset, MountPreset::Recommends);
    }

    // =========================================================================
    // IsolationConfig mount tests
    // =========================================================================

    #[test]
    fn test_isolation_config_resolved_mounts_empty() {
        let config = IsolationConfig::chroot();
        assert!(config.resolved_mounts().is_empty());
    }

    #[test]
    fn test_isolation_config_resolved_mounts_preset_only() {
        let config = IsolationConfig::Chroot {
            preset: Some(MountPreset::Recommends),
            mounts: vec![],
        };
        let mounts = config.resolved_mounts();
        assert_eq!(mounts.len(), 6);
    }

    #[test]
    fn test_isolation_config_resolved_mounts_custom_only() {
        let config = IsolationConfig::Chroot {
            preset: None,
            mounts: vec![MountEntry {
                source: "proc".to_string(),
                target: "/proc".into(),
                options: vec![],
            }],
        };
        let mounts = config.resolved_mounts();
        assert_eq!(mounts.len(), 1);
    }

    #[test]
    fn test_isolation_config_resolved_mounts_merge_replaces_preset() {
        let config = IsolationConfig::Chroot {
            preset: Some(MountPreset::Recommends),
            mounts: vec![MountEntry {
                source: "/dev".to_string(),
                target: "/dev".into(),
                options: vec!["bind".to_string()],
            }],
        };
        let mounts = config.resolved_mounts();

        // Original preset has 6, custom replaces /dev (devtmpfs), so 5 preset + 1 custom = 6
        assert_eq!(mounts.len(), 6);

        // The /dev entry should be the custom bind mount, not the preset devtmpfs
        let dev_entry = mounts.iter().find(|m| m.target.as_str() == "/dev").unwrap();
        assert_eq!(dev_entry.source, "/dev");
        assert!(dev_entry.is_bind_mount());
    }

    #[test]
    fn test_isolation_config_has_mounts() {
        assert!(!IsolationConfig::chroot().has_mounts());
        assert!(
            IsolationConfig::Chroot {
                preset: Some(MountPreset::Recommends),
                mounts: vec![],
            }
            .has_mounts()
        );
        assert!(
            IsolationConfig::Chroot {
                preset: None,
                mounts: vec![MountEntry {
                    source: "proc".to_string(),
                    target: "/proc".into(),
                    options: vec![],
                }],
            }
            .has_mounts()
        );
    }

    #[test]
    fn test_isolation_config_chroot_with_preset_deserialize() {
        let yaml = "type: chroot\npreset: recommends\n";
        let config: IsolationConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            IsolationConfig::Chroot { preset, mounts } => {
                assert_eq!(preset, Some(MountPreset::Recommends));
                assert!(mounts.is_empty());
            }
        }
    }

    #[test]
    fn test_isolation_config_chroot_with_mounts_deserialize() {
        let yaml = "type: chroot\nmounts:\n  - source: proc\n    target: /proc\n";
        let config: IsolationConfig = serde_yaml::from_str(yaml).unwrap();
        match config {
            IsolationConfig::Chroot { preset, mounts } => {
                assert!(preset.is_none());
                assert_eq!(mounts.len(), 1);
                assert_eq!(mounts[0].source, "proc");
            }
        }
    }

    // =========================================================================
    // validate_mount_order tests
    // =========================================================================

    #[test]
    fn test_validate_mount_order_correct() {
        let mounts = vec![
            MountEntry {
                source: "devtmpfs".to_string(),
                target: "/dev".into(),
                options: vec![],
            },
            MountEntry {
                source: "devpts".to_string(),
                target: "/dev/pts".into(),
                options: vec![],
            },
        ];
        assert!(validate_mount_order(&mounts).is_ok());
    }

    #[test]
    fn test_validate_mount_order_incorrect() {
        let mounts = vec![
            MountEntry {
                source: "devpts".to_string(),
                target: "/dev/pts".into(),
                options: vec![],
            },
            MountEntry {
                source: "devtmpfs".to_string(),
                target: "/dev".into(),
                options: vec![],
            },
        ];
        let err = validate_mount_order(&mounts).unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("mount order error"));
    }

    #[test]
    fn test_mount_entry_validate_rejects_pseudo_fs_with_bind() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec!["bind".to_string()],
        };
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("pseudo-filesystem"));
        assert!(err.to_string().contains("bind mount"));
    }

    #[test]
    fn test_validate_mount_order_empty() {
        assert!(validate_mount_order(&[]).is_ok());
    }

    #[test]
    fn test_validate_mount_order_single() {
        let mounts = vec![MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        }];
        assert!(validate_mount_order(&mounts).is_ok());
    }

    #[test]
    fn test_validate_mount_order_independent_paths_ok() {
        let mounts = vec![
            MountEntry {
                source: "sysfs".to_string(),
                target: "/sys".into(),
                options: vec![],
            },
            MountEntry {
                source: "proc".to_string(),
                target: "/proc".into(),
                options: vec![],
            },
        ];
        assert!(validate_mount_order(&mounts).is_ok());
    }

    #[test]
    fn test_mount_entry_validate_rejects_empty_source() {
        let entry = MountEntry {
            source: "".to_string(),
            target: "/mnt".into(),
            options: vec![],
        };
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn test_mount_entry_validate_rejects_root_target() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/".into(),
            options: vec![],
        };
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("not allowed"));
    }

    #[test]
    fn test_mount_entry_validate_rejects_unknown_relative_source() {
        let entry = MountEntry {
            source: "foobar".to_string(),
            target: "/mnt".into(),
            options: vec![],
        };
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(
            err.to_string()
                .contains("not a recognized pseudo-filesystem")
        );
    }

    #[test]
    fn test_mount_preset_recommends_entries_are_valid() {
        let entries = MountPreset::Recommends.to_entries();
        for entry in &entries {
            entry.validate().unwrap_or_else(|e| {
                panic!("preset entry {} -> {} should be valid: {}", entry.source, entry.target, e)
            });
        }
    }

    #[test]
    fn test_mount_preset_recommends_entries_satisfy_mount_order() {
        let entries = MountPreset::Recommends.to_entries();
        validate_mount_order(&entries).unwrap();
    }

    #[test]
    fn test_resolved_mounts_merge_preserves_mount_order() {
        // Custom /dev override should be placed at the original /dev position
        // (before /dev/pts), not appended at the end
        let config = IsolationConfig::Chroot {
            preset: Some(MountPreset::Recommends),
            mounts: vec![MountEntry {
                source: "/dev".to_string(),
                target: "/dev".into(),
                options: vec!["bind".to_string()],
            }],
        };
        let mounts = config.resolved_mounts();
        assert_eq!(mounts.len(), 6);

        // /dev should come before /dev/pts
        let dev_pos = mounts
            .iter()
            .position(|m| m.target.as_str() == "/dev")
            .unwrap();
        let devpts_pos = mounts
            .iter()
            .position(|m| m.target.as_str() == "/dev/pts")
            .unwrap();
        assert!(
            dev_pos < devpts_pos,
            "/dev (pos {}) should come before /dev/pts (pos {})",
            dev_pos,
            devpts_pos
        );

        // The merged result should pass mount order validation
        validate_mount_order(&mounts).unwrap();
    }

    #[test]
    fn test_resolved_mounts_merge_multiple_overrides() {
        let config = IsolationConfig::Chroot {
            preset: Some(MountPreset::Recommends),
            mounts: vec![
                MountEntry {
                    source: "tmpfs".to_string(),
                    target: "/tmp".into(),
                    options: vec!["size=2G".to_string()],
                },
                MountEntry {
                    source: "/dev".to_string(),
                    target: "/dev".into(),
                    options: vec!["bind".to_string()],
                },
            ],
        };
        let mounts = config.resolved_mounts();
        assert_eq!(mounts.len(), 6);

        // Verify custom entries replaced the presets
        let dev_entry = mounts.iter().find(|m| m.target.as_str() == "/dev").unwrap();
        assert!(dev_entry.is_bind_mount());

        let tmp_entry = mounts.iter().find(|m| m.target.as_str() == "/tmp").unwrap();
        assert!(tmp_entry.options.contains(&"size=2G".to_string()));

        // The merged result should pass mount order validation
        validate_mount_order(&mounts).unwrap();
    }

    #[test]
    fn test_mount_entry_validate_rejects_regular_source_with_dotdot() {
        let entry = MountEntry {
            source: "/mnt/../etc".to_string(),
            target: "/mnt".into(),
            options: vec![],
        };
        let err = entry.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains(".."));
    }

    #[test]
    fn test_mount_entry_build_mount_spec_with_path() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        };
        let spec = entry.build_mount_spec_with_path(Utf8Path::new("/verified/rootfs/proc"), None);
        assert_eq!(spec.command, "mount");
        assert_eq!(spec.args, vec!["-t", "proc", "proc", "/verified/rootfs/proc"]);
    }

    #[test]
    fn test_mount_entry_build_mount_spec_with_path_bind() {
        let entry = MountEntry {
            source: "/dev".to_string(),
            target: "/dev".into(),
            options: vec!["bind".to_string()],
        };
        let spec = entry.build_mount_spec_with_path(
            Utf8Path::new("/verified/rootfs/dev"),
            Some(PrivilegeMethod::Sudo),
        );
        assert_eq!(spec.command, "mount");
        assert_eq!(spec.args, vec!["-o", "bind", "/dev", "/verified/rootfs/dev"]);
        assert_eq!(spec.privilege, Some(PrivilegeMethod::Sudo));
    }
}
