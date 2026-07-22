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
use std::net::IpAddr;

use camino::{Utf8Path, Utf8PathBuf};
#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::bootstrap::{
    BootstrapBackend, RootfsOutput, debootstrap::DebootstrapConfig, mmdebstrap::MmdebstrapConfig,
};
use crate::error::RsdebstrapError;
use crate::executor::CommandSpec;
use crate::isolation::{ChrootProvider, IsolationProvider};
use crate::phase::{AssembleConfig, PrepareConfig, ProvisionTask};
use crate::pipeline::Pipeline;
use crate::privilege::{Privilege, PrivilegeDefaults, PrivilegeMethod};

/// Known pseudo-filesystem source names.
///
/// These are used to determine the correct `mount -t` type argument.
const PSEUDO_FS_TYPES: &[&str] = &["proc", "sysfs", "devpts", "devtmpfs", "tmpfs"];

/// Mount preset defining a predefined set of mount entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
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

/// Configuration for resolv.conf setup within a chroot.
///
/// Supports two mutually exclusive modes:
/// - `copy: true` — copies the host's /etc/resolv.conf into the chroot
/// - `name_servers` / `search` — generates resolv.conf from explicit values
///
/// Limits follow the resolv.conf specification: max 3 nameservers,
/// max 6 search domains (total 256 characters).
//
// No `JsonSchema` derive: this is a runtime-only type (see `src/isolation/resolv_conf.rs`)
// and is not reachable from `Profile`, so it contributes nothing to the generated schema.
// The profile-facing DNS shapes are `prepare::ResolvConfTask` / `assemble::AssembleResolvConfTask`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvConfConfig {
    /// Copy host's /etc/resolv.conf into the chroot (following symlinks).
    #[serde(default)]
    pub copy: bool,
    /// Nameserver IP addresses to write to resolv.conf.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub name_servers: Vec<IpAddr>,
    /// Search domains to write to resolv.conf.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search: Vec<String>,
}

impl ResolvConfConfig {
    /// Validates the resolv.conf configuration.
    ///
    /// Checks mutual exclusivity of `copy` vs `name_servers`/`search`,
    /// and enforces resolv.conf specification limits.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        if self.copy {
            if !self.name_servers.is_empty() {
                return Err(RsdebstrapError::Validation(
                    "resolv_conf: 'copy: true' and 'name_servers' are mutually exclusive"
                        .to_string(),
                ));
            }
            if !self.search.is_empty() {
                return Err(RsdebstrapError::Validation(
                    "resolv_conf: 'copy: true' and 'search' are mutually exclusive".to_string(),
                ));
            }
        }
        if !self.copy && self.name_servers.is_empty() {
            return Err(RsdebstrapError::Validation(
                "resolv_conf: 'name_servers' is required when 'copy' is not enabled".to_string(),
            ));
        }
        if self.name_servers.len() > 3 {
            return Err(RsdebstrapError::Validation(format!(
                "resolv_conf: at most 3 nameservers allowed (got {})",
                self.name_servers.len()
            )));
        }
        if self.search.len() > 6 {
            return Err(RsdebstrapError::Validation(format!(
                "resolv_conf: at most 6 search domains allowed (got {})",
                self.search.len()
            )));
        }
        let total_search_len: usize = self.search.iter().map(|s| s.len()).sum::<usize>()
            + self.search.len().saturating_sub(1); // spaces between domains
        if total_search_len > 256 {
            return Err(RsdebstrapError::Validation(format!(
                "resolv_conf: search domains total length exceeds 256 characters (got {})",
                total_search_len
            )));
        }
        for domain in &self.search {
            if domain.trim().is_empty() {
                return Err(RsdebstrapError::Validation(
                    "resolv_conf: search domain must not be empty".to_string(),
                ));
            }
            if domain.contains('\n') || domain.contains('\r') {
                return Err(RsdebstrapError::Validation(format!(
                    "resolv_conf: search domain '{}' must not contain newline characters",
                    domain.escape_default()
                )));
            }
            if domain.contains(' ') {
                return Err(RsdebstrapError::Validation(format!(
                    "resolv_conf: search domain '{}' must not contain spaces",
                    domain
                )));
            }
        }
        Ok(())
    }
}

/// A single mount entry specifying what to mount into the rootfs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct MountEntry {
    /// Device name or path (e.g., "proc", "sysfs", "/dev").
    #[serde(deserialize_with = "crate::de::string")]
    pub source: String,
    /// Mount point inside the rootfs (absolute path).
    #[serde(deserialize_with = "crate::de::path")]
    #[cfg_attr(feature = "schema", schemars(with = "crate::schema::Utf8PathSchema"))]
    pub target: Utf8PathBuf,
    /// Mount options (e.g., "bind", "nosuid"). Joined with "," for `-o`.
    #[serde(default, deserialize_with = "crate::de::string_list")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<Vec<String>>"))]
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

    /// Builds a `CommandSpec` for the `mount` command using a pre-validated absolute target path.
    ///
    /// Accepts an already-validated absolute path (e.g., from
    /// [`safe_create_mount_point()`](crate::isolation::mount::safe_create_mount_point))
    /// instead of computing it from rootfs + target.
    ///
    /// For pseudo-filesystems, generates: `mount -t <source> [-o opts] <source> <abs_target>`
    /// For others: `mount [-o opts] <source> <abs_target>`
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

    /// Builds a `CommandSpec` for the `umount` command using a pre-validated absolute target path.
    ///
    /// Accepts an already-validated absolute path (e.g., stored by
    /// [`RootfsMounts`](crate::isolation::mount::RootfsMounts) after a successful mount)
    /// instead of computing it from rootfs + target.
    pub fn build_umount_spec_with_path(
        &self,
        abs_target: &Utf8Path,
        privilege: Option<PrivilegeMethod>,
    ) -> CommandSpec {
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

        crate::phase::validate_no_parent_dirs(&self.target, "mount target")?;

        if self.is_bind_mount() {
            let source_path = Utf8Path::new(&self.source);
            if !source_path.starts_with("/") {
                return Err(RsdebstrapError::Validation(format!(
                    "bind mount source '{}' must be an absolute path",
                    self.source
                )));
            }
            crate::phase::validate_no_parent_dirs(source_path, "bind mount source")?;
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
            crate::phase::validate_no_parent_dirs(source_path, "mount source")?;
        }

        Ok(())
    }
}

/// Bootstrap backend configuration.
///
/// This enum represents the different bootstrap tools that can be used.
/// The `type` field in YAML determines which variant is used.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
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
/// The `type` key selects the backend used to run commands inside the rootfs; `chroot` is
/// currently the only backend. `type` is required whenever an `isolation` map is written
/// out — the chroot default applies only when the surrounding `isolation` key (e.g.
/// `defaults.isolation`) is omitted entirely.
// Internally tagged like `Bootstrap` (rather than a plain struct) so each backend keeps its
// own payload struct as an extension point for backend-specific options (bwrap, nspawn, …).
// `deny_unknown_fields` would be a serde no-op on the enum itself, so strictness lives on
// the per-variant payload structs: serde consumes the `type` tag when selecting the variant
// and hands only the remaining keys to the payload, whose `deny_unknown_fields` then
// rejects typo'd keys (see the `Bootstrap` note in ARCHITECTURE.md).
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IsolationConfig {
    /// Run commands inside the rootfs via `chroot`.
    Chroot(ChrootIsolation),
}

/// Options for the `chroot` isolation backend (currently none).
// A braced (named-field) empty struct, not a unit struct: internally tagged variants need a
// map-shaped payload to serialize, and only the braced form gives `deny_unknown_fields` a
// struct visitor that rejects `{type: chroot, <typo>: ...}`.
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ChrootIsolation {}

impl Default for IsolationConfig {
    /// The backend used when no `isolation` key is configured: chroot.
    fn default() -> Self {
        Self::chroot()
    }
}

impl IsolationConfig {
    /// Creates a default chroot config.
    pub fn chroot() -> Self {
        Self::Chroot(ChrootIsolation {})
    }

    /// Returns a boxed isolation provider instance.
    ///
    /// This allows calling `IsolationProvider` methods without matching
    /// on each variant explicitly.
    pub fn as_provider(&self) -> Box<dyn IsolationProvider> {
        match self {
            Self::Chroot(_) => Box::new(ChrootProvider),
        }
    }
}

/// Default settings for mitamae tasks.
///
/// Allows specifying architecture-specific binary paths that apply to all
/// mitamae tasks unless overridden at the task level.
#[derive(Debug, Deserialize, Clone, Default)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct MitamaeDefaults {
    /// Architecture-specific binary paths (key: "x86_64", "aarch64", etc.)
    #[serde(default, deserialize_with = "crate::de::path_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "Option<std::collections::HashMap<String, crate::schema::Utf8PathSchema>>"
        )
    )]
    pub binary: HashMap<String, Utf8PathBuf>,
}

/// Default settings that apply across the profile.
///
/// Groups configuration defaults like isolation backend.
/// If omitted in YAML, all fields use their respective defaults.
#[derive(Debug, Deserialize, Clone, Default)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Isolation backend for running commands in rootfs (default: chroot)
    #[serde(default)]
    pub isolation: IsolationConfig,
    /// Default settings for mitamae tasks
    #[serde(default, deserialize_with = "crate::de::null_to_default")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<MitamaeDefaults>"))]
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
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Target directory path for the bootstrap operation
    #[serde(deserialize_with = "crate::de::path")]
    #[cfg_attr(feature = "schema", schemars(with = "crate::schema::Utf8PathSchema"))]
    pub dir: Utf8PathBuf,
    /// Default settings (isolation backend, etc.)
    #[serde(default, deserialize_with = "crate::de::null_to_default")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<Defaults>"))]
    pub defaults: Defaults,
    /// Bootstrap tool configuration
    pub bootstrap: Bootstrap,
    /// Prepare tasks to run before provisioning (optional)
    #[serde(default, deserialize_with = "crate::de::null_to_default")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<PrepareConfig>"))]
    pub prepare: PrepareConfig,
    /// Main provisioning tasks (optional)
    #[serde(default, deserialize_with = "crate::de::null_to_default")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<Vec<ProvisionTask>>"))]
    pub provision: Vec<ProvisionTask>,
    /// Assemble tasks to run after provisioning (optional)
    #[serde(default, deserialize_with = "crate::de::null_to_default")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<AssembleConfig>"))]
    pub assemble: AssembleConfig,
}

impl Profile {
    /// Creates a `Pipeline` from this profile's task phases.
    pub fn pipeline(&self) -> Pipeline<'_> {
        Pipeline::new(&self.prepare, &self.provision, &self.assemble)
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

        // Validate resolv_conf configuration
        self.validate_resolv_conf()?;

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
        // The named-field `prepare.mount` guarantees at most one mount task.
        match &self.prepare.mount {
            Some(task) if task.has_mounts() => {}
            _ => return Ok(()),
        };

        // No isolation guard: `IsolationConfig` has a single `Chroot` variant, so
        // `defaults.isolation` is always chroot and mounts (which assume a chroot rootfs)
        // can never observe a non-chroot backend. Reintroduce a guard next to a second
        // backend if one is ever added, where it would be reachable and testable.

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

        // Mount entry validation and mount order are handled by MountTask::validate()
        // which is called by the pipeline validation path.
        // Here we only need to check privilege requirements.

        Ok(())
    }

    /// Validates resolv_conf-related configuration.
    fn validate_resolv_conf(&self) -> Result<(), RsdebstrapError> {
        // The named-field `prepare.resolv_conf` guarantees at most one task.
        // No isolation guard here for the same reason as `validate_mounts`: the sole
        // `IsolationConfig::Chroot` variant makes `defaults.isolation` always chroot.
        if let Some(task) = &self.prepare.resolv_conf {
            task.config().validate()?;
        }

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
pub(crate) fn validate_mount_order(mounts: &[MountEntry]) -> Result<(), RsdebstrapError> {
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

fn format_yaml_parse_error(err: yaml_serde::Error, file_path: &Utf8Path) -> RsdebstrapError {
    // yaml_serde sometimes embeds the location in its Display output
    // ("... at line X column Y") and sometimes exposes it only via location()
    // (e.g. "missing field `dir`"). We render the message as-is and append the
    // location from location() only when the message does not already mention
    // that line. The check keys off the numeric line value (stable data), not
    // yaml_serde's exact wording, so a future change to its phrasing degrades to
    // a harmless duplicate location rather than silently dropping it.
    let msg = err.to_string();
    let suffix = match err.location() {
        Some(loc) if !msg.contains(&format!("line {}", loc.line())) => {
            format!(" (line {}, column {})", loc.line(), loc.column())
        }
        _ => String::new(),
    };
    RsdebstrapError::Config(format!("{}: YAML parse error: {}{}", file_path, msg, suffix))
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
    yaml_serde::from_reader(reader).map_err(|e| format_yaml_parse_error(e, file_path))
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

    for task in profile.provision.iter_mut() {
        if let ProvisionTask::Mitamae(mitamae_task) = task
            && let Some(binary) = default_binary
        {
            mitamae_task.set_binary_if_absent(binary);
        }
        task.resolve_privilege(privilege_defaults)?;
        task.resolve_isolation(&isolation_defaults);
    }

    // Resolve privilege for assemble tasks
    if let Some(task) = profile.assemble.resolv_conf.as_mut() {
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

    for task in profile.provision.iter_mut() {
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

    // Checked before path resolution: joining an empty `dir` onto the profile's
    // directory would silently target that directory itself.
    if profile.dir.as_str().is_empty() {
        return Err(RsdebstrapError::Validation("dir must not be empty".to_string()));
    }

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

    /// Generates a yaml_serde::Error by attempting to parse invalid YAML.
    fn make_yaml_error(yaml: &str) -> yaml_serde::Error {
        yaml_serde::from_str::<Profile>(yaml).unwrap_err()
    }

    #[test]
    fn test_format_yaml_parse_error_with_location() {
        // A type error embeds the location directly in yaml_serde's Display output.
        let err = make_yaml_error("dir: [invalid, list]");
        let result = format_yaml_parse_error(err, Utf8Path::new("/test/profile.yml"));
        let msg = result.to_string();
        assert!(msg.contains("/test/profile.yml"), "should contain file path: {}", msg);
        assert!(msg.contains("YAML parse error"), "should contain 'YAML parse error': {}", msg);
        assert!(msg.contains("line "), "should contain line info: {}", msg);
        assert!(msg.contains("column "), "should contain column info: {}", msg);
    }

    #[test]
    fn test_format_yaml_parse_error_no_duplicate_location() {
        // yaml_serde already embeds the location in this error's message, so we must
        // not append a second copy from location().
        let err = make_yaml_error("dir: [invalid, list]");
        let result = format_yaml_parse_error(err, Utf8Path::new("/test/profile.yml"));
        let msg = result.to_string();
        assert_eq!(msg.matches("line ").count(), 1, "location must not be duplicated: {}", msg);
        assert!(
            !msg.contains(" (line "),
            "our appended suffix must be absent when yaml_serde embeds the location: {}",
            msg
        );
    }

    #[test]
    fn test_format_yaml_parse_error_appends_location_when_absent() {
        // A "missing field" error carries a location() but omits it from Display,
        // so we append it ourselves rather than dropping it.
        let err = make_yaml_error("");
        let result = format_yaml_parse_error(err, Utf8Path::new("/test/empty.yml"));
        let msg = result.to_string();
        assert!(msg.contains("/test/empty.yml"), "should contain file path: {}", msg);
        assert!(msg.contains("YAML parse error"), "should contain 'YAML parse error': {}", msg);
        assert!(
            msg.contains(" (line "),
            "location from location() should be appended when the message lacks it: {}",
            msg
        );
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
    fn test_mount_entry_build_mount_spec_with_path_pseudo_fs() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        };
        let spec = entry.build_mount_spec_with_path(Utf8Path::new("/rootfs/proc"), None);
        assert_eq!(spec.command, "mount");
        assert_eq!(spec.args, vec!["-t", "proc", "proc", "/rootfs/proc"]);
    }

    #[test]
    fn test_mount_entry_build_mount_spec_with_path_pseudo_fs_with_options() {
        let entry = MountEntry {
            source: "devpts".to_string(),
            target: "/dev/pts".into(),
            options: vec!["gid=5".to_string(), "mode=620".to_string()],
        };
        let spec = entry.build_mount_spec_with_path(Utf8Path::new("/rootfs/dev/pts"), None);
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
    fn test_mount_entry_build_mount_spec_with_path_bind() {
        let entry = MountEntry {
            source: "/dev".to_string(),
            target: "/dev".into(),
            options: vec!["bind".to_string()],
        };
        let spec = entry.build_mount_spec_with_path(Utf8Path::new("/rootfs/dev"), None);
        assert_eq!(spec.command, "mount");
        assert_eq!(spec.args, vec!["-o", "bind", "/dev", "/rootfs/dev"]);
    }

    #[test]
    fn test_mount_entry_build_umount_spec_with_path() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        };
        let spec = entry.build_umount_spec_with_path(Utf8Path::new("/rootfs/proc"), None);
        assert_eq!(spec.command, "umount");
        assert_eq!(spec.args, vec!["/rootfs/proc"]);
    }

    #[test]
    fn test_mount_entry_build_mount_spec_with_path_privilege() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        };
        let spec = entry
            .build_mount_spec_with_path(Utf8Path::new("/rootfs/proc"), Some(PrivilegeMethod::Sudo));
        assert_eq!(spec.privilege, Some(PrivilegeMethod::Sudo));
    }

    #[test]
    fn test_mount_entry_build_umount_spec_with_path_privilege() {
        let entry = MountEntry {
            source: "proc".to_string(),
            target: "/proc".into(),
            options: vec![],
        };
        let spec = entry.build_umount_spec_with_path(
            Utf8Path::new("/rootfs/proc"),
            Some(PrivilegeMethod::Sudo),
        );
        assert_eq!(spec.command, "umount");
        assert_eq!(spec.args, vec!["/rootfs/proc"]);
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
    fn test_mount_entry_validate_valid_bind_mount() {
        // /tmp is guaranteed to exist on any system
        let entry = MountEntry {
            source: "/tmp".to_string(),
            target: "/tmp".into(),
            options: vec!["bind".to_string()],
        };
        assert!(entry.validate().is_ok());
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
        let yaml = yaml_serde::to_string(&entry).unwrap();
        let deserialized: MountEntry = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(entry, deserialized);
    }

    #[test]
    fn test_mount_entry_deserialize_without_options() {
        let yaml = "source: proc\ntarget: /proc\n";
        let entry: MountEntry = yaml_serde::from_str(yaml).unwrap();
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
        let preset: MountPreset = yaml_serde::from_str("recommends").unwrap();
        assert_eq!(preset, MountPreset::Recommends);
    }

    // =========================================================================
    // IsolationConfig tests
    // =========================================================================

    #[test]
    fn test_isolation_config_serialize_deserialize_roundtrip() {
        let config = IsolationConfig::chroot();
        let yaml = yaml_serde::to_string(&config).unwrap();
        let deserialized: IsolationConfig = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(config, deserialized);
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

    // =========================================================================
    // ResolvConfConfig tests
    // =========================================================================

    #[test]
    fn test_resolv_conf_deserialize_copy() {
        let yaml = "copy: true";
        let config: ResolvConfConfig = yaml_serde::from_str(yaml).unwrap();
        assert!(config.copy);
        assert!(config.name_servers.is_empty());
        assert!(config.search.is_empty());
    }

    #[test]
    fn test_resolv_conf_deserialize_name_servers() {
        let yaml = "name_servers:\n  - 127.0.0.1\n";
        let config: ResolvConfConfig = yaml_serde::from_str(yaml).unwrap();
        assert!(!config.copy);
        assert_eq!(config.name_servers.len(), 1);
        assert_eq!(config.name_servers[0].to_string(), "127.0.0.1");
    }

    #[test]
    fn test_resolv_conf_deserialize_ipv6() {
        let yaml = "name_servers:\n  - '::1'\nsearch:\n  - example.com\n";
        let config: ResolvConfConfig = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(config.name_servers[0].to_string(), "::1");
        assert_eq!(config.search, vec!["example.com"]);
    }

    #[test]
    fn test_resolv_conf_validate_copy_and_name_servers_conflict() {
        let config = ResolvConfConfig {
            copy: true,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![],
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn test_resolv_conf_validate_copy_and_search_conflict() {
        let config = ResolvConfConfig {
            copy: true,
            name_servers: vec![],
            search: vec!["example.com".to_string()],
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn test_resolv_conf_validate_empty_config() {
        let config = ResolvConfConfig {
            copy: false,
            name_servers: vec![],
            search: vec![],
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("name_servers"));
    }

    #[test]
    fn test_resolv_conf_validate_search_only_requires_nameservers() {
        let config = ResolvConfConfig {
            copy: false,
            name_servers: vec![],
            search: vec!["example.com".to_string()],
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("name_servers"));
    }

    #[test]
    fn test_resolv_conf_validate_too_many_nameservers() {
        let config = ResolvConfConfig {
            copy: false,
            name_servers: vec![
                "8.8.8.8".parse().unwrap(),
                "8.8.4.4".parse().unwrap(),
                "1.1.1.1".parse().unwrap(),
                "1.0.0.1".parse().unwrap(),
            ],
            search: vec![],
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("at most 3"));
    }

    #[test]
    fn test_resolv_conf_validate_too_many_search_domains() {
        let config = ResolvConfConfig {
            copy: false,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![
                "a.com".to_string(),
                "b.com".to_string(),
                "c.com".to_string(),
                "d.com".to_string(),
                "e.com".to_string(),
                "f.com".to_string(),
                "g.com".to_string(),
            ],
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("at most 6"));
    }

    #[test]
    fn test_resolv_conf_validate_search_total_length_exceeded() {
        // Create 6 domains with very long names that exceed 256 chars total
        let long_domain = "a".repeat(50);
        let config = ResolvConfConfig {
            copy: false,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec![long_domain; 6],
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("256"));
    }

    #[test]
    fn test_resolv_conf_validate_empty_search_domain() {
        let config = ResolvConfConfig {
            copy: false,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec!["".to_string()],
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn test_resolv_conf_validate_search_domain_with_space() {
        let config = ResolvConfConfig {
            copy: false,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec!["example .com".to_string()],
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("spaces"));
    }

    #[test]
    fn test_resolv_conf_validate_valid_copy() {
        let config = ResolvConfConfig {
            copy: true,
            name_servers: vec![],
            search: vec![],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_resolv_conf_validate_valid_nameservers_and_search() {
        let config = ResolvConfConfig {
            copy: false,
            name_servers: vec!["8.8.8.8".parse().unwrap()],
            search: vec!["example.com".to_string()],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_resolv_conf_validate_valid_max_nameservers() {
        let config = ResolvConfConfig {
            copy: false,
            name_servers: vec![
                "8.8.8.8".parse().unwrap(),
                "8.8.4.4".parse().unwrap(),
                "1.1.1.1".parse().unwrap(),
            ],
            search: vec![],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_resolv_conf_serialize_deserialize_roundtrip() {
        use std::net::IpAddr;
        let config = ResolvConfConfig {
            copy: false,
            name_servers: vec![
                "8.8.8.8".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap(),
            ],
            search: vec!["example.com".to_string()],
        };
        let yaml = yaml_serde::to_string(&config).unwrap();
        let deserialized: ResolvConfConfig = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(config, deserialized);
    }

    // =========================================================================
    // Profile::validate_mounts / validate_resolv_conf tests
    //
    // `IsolationConfig` has a single `Chroot` variant, so `defaults.isolation`
    // is always chroot; the former "mounts/resolv_conf require chroot
    // isolation" guards were removed as unreachable dead code. These tests
    // cover the resulting behavior of both private validators directly.
    // =========================================================================

    /// Builds a minimal valid `Profile` YAML document, with `extra` spliced in
    /// as additional top-level keys (e.g. `defaults:`, `prepare:`).
    fn minimal_profile_yaml(extra: &str) -> String {
        format!(
            "dir: /tmp/rootfs\nbootstrap:\n  type: mmdebstrap\n  suite: trixie\n  target: rootfs\n{}",
            extra
        )
    }

    fn parse_profile(yaml: &str) -> Profile {
        yaml_serde::from_str(yaml)
            .unwrap_or_else(|e| panic!("failed to parse profile: {e}\nyaml:\n{yaml}"))
    }

    #[test]
    fn test_validate_mounts_no_mount_task_is_ok() {
        let profile = parse_profile(&minimal_profile_yaml(""));
        assert!(profile.validate_mounts().is_ok());
    }

    #[test]
    fn test_validate_mounts_empty_mount_task_is_ok() {
        // No preset and no custom mounts: has_mounts() is false, so
        // validate_mounts() must short-circuit to Ok without requiring privilege.
        let yaml = minimal_profile_yaml("prepare:\n  mount:\n    mounts: []\n");
        let profile = parse_profile(&yaml);
        assert!(profile.validate_mounts().is_ok());
    }

    #[test]
    fn test_validate_mounts_requires_privilege() {
        let yaml = minimal_profile_yaml("prepare:\n  mount:\n    preset: recommends\n");
        let profile = parse_profile(&yaml);
        let err = profile.validate_mounts().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(
            err.to_string()
                .contains("defaults.privilege must be configured"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_validate_mounts_custom_mounts_without_preset_requires_privilege() {
        let yaml = minimal_profile_yaml(
            "prepare:\n  mount:\n    mounts:\n      - source: proc\n        target: /proc\n",
        );
        let profile = parse_profile(&yaml);
        let err = profile.validate_mounts().unwrap_err();
        assert!(
            err.to_string()
                .contains("defaults.privilege must be configured")
        );
    }

    #[test]
    fn test_validate_mounts_missing_privilege_error_is_not_isolation_related() {
        // Regression test for the removed "mounts require chroot isolation"
        // guard: the only error surfaced for a missing-privilege config must
        // be about privilege, never about isolation/chroot.
        let yaml = minimal_profile_yaml("prepare:\n  mount:\n    preset: recommends\n");
        let profile = parse_profile(&yaml);
        let err = profile.validate_mounts().unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("isolation"), "unexpected isolation-related error: {msg}");
        assert!(!msg.contains("chroot"), "unexpected chroot-related error: {msg}");
    }

    #[test]
    fn test_validate_mounts_with_default_isolation_and_privilege_succeeds() {
        // `defaults.isolation` is omitted, so it takes its default (chroot).
        // With privilege configured, no isolation guard blocks validation
        // (mount/umount are expected to be present in PATH on the test host).
        let yaml = minimal_profile_yaml(
            "defaults:\n  privilege:\n    method: sudo\nprepare:\n  mount:\n    preset: recommends\n",
        );
        let profile = parse_profile(&yaml);
        let result = profile.validate_mounts();
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.unwrap_err());
    }

    #[test]
    fn test_validate_mounts_with_explicit_chroot_isolation_and_privilege_succeeds() {
        let yaml = minimal_profile_yaml(
            "defaults:\n  isolation:\n    type: chroot\n  privilege:\n    method: sudo\n\
             prepare:\n  mount:\n    preset: recommends\n",
        );
        let profile = parse_profile(&yaml);
        let result = profile.validate_mounts();
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.unwrap_err());
    }

    #[test]
    fn test_validate_resolv_conf_no_task_is_ok() {
        let profile = parse_profile(&minimal_profile_yaml(""));
        assert!(profile.validate_resolv_conf().is_ok());
    }

    #[test]
    fn test_validate_resolv_conf_valid_copy_is_ok_with_default_isolation() {
        let yaml = minimal_profile_yaml("prepare:\n  resolv_conf:\n    copy: true\n");
        let profile = parse_profile(&yaml);
        assert!(profile.validate_resolv_conf().is_ok());
    }

    #[test]
    fn test_validate_resolv_conf_valid_generate_is_ok() {
        let yaml = minimal_profile_yaml(
            "prepare:\n  resolv_conf:\n    name_servers:\n      - 8.8.8.8\n    search:\n      - example.com\n",
        );
        let profile = parse_profile(&yaml);
        assert!(profile.validate_resolv_conf().is_ok());
    }

    #[test]
    fn test_validate_resolv_conf_propagates_underlying_validation_error() {
        // No isolation guard exists anymore to short-circuit before the
        // underlying `ResolvConfConfig::validate()` call, so an invalid task
        // (neither `copy` nor `name_servers`) must surface *its* error.
        let yaml =
            minimal_profile_yaml("prepare:\n  resolv_conf:\n    search:\n      - example.com\n");
        let profile = parse_profile(&yaml);
        let err = profile.validate_resolv_conf().unwrap_err();
        assert!(matches!(err, RsdebstrapError::Validation(_)));
        assert!(err.to_string().contains("name_servers"), "unexpected error: {err}");
    }

    #[test]
    fn test_validate_resolv_conf_error_is_not_isolation_related() {
        let yaml = minimal_profile_yaml(
            "prepare:\n  resolv_conf:\n    copy: true\n    name_servers:\n      - 8.8.8.8\n",
        );
        let profile = parse_profile(&yaml);
        let err = profile.validate_resolv_conf().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mutually exclusive"), "unexpected error: {msg}");
        assert!(!msg.contains("isolation"), "unexpected isolation-related error: {msg}");
        assert!(!msg.contains("chroot"), "unexpected chroot-related error: {msg}");
    }

    #[test]
    fn test_validate_resolv_conf_with_explicit_chroot_isolation_still_validates() {
        let yaml = minimal_profile_yaml(
            "defaults:\n  isolation:\n    type: chroot\nprepare:\n  resolv_conf:\n    copy: true\n",
        );
        let profile = parse_profile(&yaml);
        assert!(profile.validate_resolv_conf().is_ok());
    }
}
