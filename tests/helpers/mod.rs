#![allow(dead_code)]

use std::cell::RefCell;
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::{LazyLock, Mutex};

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use rsdebstrap::RsdebstrapError;
use rsdebstrap::bootstrap::debootstrap::{self, DebootstrapConfig};
use rsdebstrap::bootstrap::mmdebstrap::{self, MmdebstrapConfig};
use rsdebstrap::config::{Bootstrap, Profile, load_profile};
use rsdebstrap::executor::ExecutionResult;
use rsdebstrap::isolation::IsolationContext;
use rsdebstrap::privilege::Privilege;
use tempfile::NamedTempFile;
use tracing::warn;

/// Global mutex to serialize tests that modify the current working directory.
/// This prevents parallel tests from interfering with each other.
pub static CWD_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[macro_export]
macro_rules! yaml {
    ($content:literal) => {
        $crate::helpers::dedent($content)
    };
}

pub fn dedent(input: &str) -> String {
    let mut lines: Vec<&str> = input.lines().collect();
    while matches!(lines.first(), Some(line) if line.trim().is_empty()) {
        lines.remove(0);
    }
    while matches!(lines.last(), Some(line) if line.trim().is_empty()) {
        lines.pop();
    }

    let min_indent = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.as_bytes()
                .iter()
                .take_while(|ch| **ch == b' ' || **ch == b'\t')
                .count()
        })
        .min()
        .unwrap_or(0);

    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = if line.len() >= min_indent {
            &line[min_indent..]
        } else {
            ""
        };
        out.push_str(trimmed);
        if idx + 1 < lines.len() {
            out.push('\n');
        }
    }
    out.push('\n');
    out
}

/// Builder for constructing `MmdebstrapConfig` in tests.
///
/// Provides a fluent API to set only the fields that differ from defaults,
/// reducing boilerplate in test code.
pub struct MmdebstrapConfigBuilder {
    suite: String,
    target: String,
    mode: mmdebstrap::Mode,
    format: mmdebstrap::Format,
    variant: mmdebstrap::Variant,
    architectures: Vec<String>,
    components: Vec<String>,
    include: Vec<String>,
    keyring: Vec<String>,
    aptopt: Vec<String>,
    dpkgopt: Vec<String>,
    setup_hook: Vec<String>,
    extract_hook: Vec<String>,
    essential_hook: Vec<String>,
    customize_hook: Vec<String>,
    mirrors: Vec<String>,
    privilege: Privilege,
}

impl MmdebstrapConfigBuilder {
    pub fn new(suite: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            suite: suite.into(),
            target: target.into(),
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
            privilege: Default::default(),
        }
    }

    pub fn mode(mut self, mode: mmdebstrap::Mode) -> Self {
        self.mode = mode;
        self
    }

    pub fn format(mut self, format: mmdebstrap::Format) -> Self {
        self.format = format;
        self
    }

    pub fn variant(mut self, variant: mmdebstrap::Variant) -> Self {
        self.variant = variant;
        self
    }

    pub fn architectures<I, S>(mut self, architectures: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.architectures = architectures.into_iter().map(Into::into).collect();
        self
    }

    pub fn components<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.components = components.into_iter().map(Into::into).collect();
        self
    }

    pub fn include<I, S>(mut self, include: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.include = include.into_iter().map(Into::into).collect();
        self
    }

    pub fn keyring<I, S>(mut self, keyring: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.keyring = keyring.into_iter().map(Into::into).collect();
        self
    }

    pub fn aptopt<I, S>(mut self, aptopt: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.aptopt = aptopt.into_iter().map(Into::into).collect();
        self
    }

    pub fn dpkgopt<I, S>(mut self, dpkgopt: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.dpkgopt = dpkgopt.into_iter().map(Into::into).collect();
        self
    }

    pub fn setup_hook<I, S>(mut self, setup_hook: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.setup_hook = setup_hook.into_iter().map(Into::into).collect();
        self
    }

    pub fn extract_hook<I, S>(mut self, extract_hook: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.extract_hook = extract_hook.into_iter().map(Into::into).collect();
        self
    }

    pub fn essential_hook<I, S>(mut self, essential_hook: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.essential_hook = essential_hook.into_iter().map(Into::into).collect();
        self
    }

    pub fn customize_hook<I, S>(mut self, customize_hook: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.customize_hook = customize_hook.into_iter().map(Into::into).collect();
        self
    }

    pub fn mirrors<I, S>(mut self, mirrors: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.mirrors = mirrors.into_iter().map(Into::into).collect();
        self
    }

    pub fn privilege(mut self, privilege: Privilege) -> Self {
        self.privilege = privilege;
        self
    }

    pub fn build(self) -> MmdebstrapConfig {
        MmdebstrapConfig {
            suite: self.suite,
            target: self.target,
            mode: self.mode,
            format: self.format,
            variant: self.variant,
            architectures: self.architectures,
            components: self.components,
            include: self.include,
            keyring: self.keyring,
            aptopt: self.aptopt,
            dpkgopt: self.dpkgopt,
            setup_hook: self.setup_hook,
            extract_hook: self.extract_hook,
            essential_hook: self.essential_hook,
            customize_hook: self.customize_hook,
            mirrors: self.mirrors,
            privilege: self.privilege,
        }
    }
}

/// Test helper to create a MmdebstrapConfig with minimal required fields.
///
/// All optional fields are initialized with their default values.
pub fn create_mmdebstrap(suite: impl Into<String>, target: impl Into<String>) -> MmdebstrapConfig {
    MmdebstrapConfigBuilder::new(suite, target).build()
}

/// Builder for constructing `DebootstrapConfig` in tests.
///
/// Provides a fluent API to set only the fields that differ from defaults,
/// reducing boilerplate in test code.
pub struct DebootstrapConfigBuilder {
    suite: String,
    target: String,
    variant: debootstrap::Variant,
    arch: Option<String>,
    components: Vec<String>,
    include: Vec<String>,
    exclude: Vec<String>,
    mirror: Option<String>,
    foreign: bool,
    merged_usr: Option<bool>,
    no_resolve_deps: bool,
    verbose: bool,
    print_debs: bool,
    privilege: Privilege,
}

impl DebootstrapConfigBuilder {
    pub fn new(suite: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            suite: suite.into(),
            target: target.into(),
            variant: Default::default(),
            arch: Default::default(),
            components: Default::default(),
            include: Default::default(),
            exclude: Default::default(),
            mirror: Default::default(),
            foreign: Default::default(),
            merged_usr: Default::default(),
            no_resolve_deps: Default::default(),
            verbose: Default::default(),
            print_debs: Default::default(),
            privilege: Default::default(),
        }
    }

    pub fn variant(mut self, variant: debootstrap::Variant) -> Self {
        self.variant = variant;
        self
    }

    pub fn arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = Some(arch.into());
        self
    }

    pub fn components<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.components = components.into_iter().map(Into::into).collect();
        self
    }

    pub fn include<I, S>(mut self, include: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.include = include.into_iter().map(Into::into).collect();
        self
    }

    pub fn exclude<I, S>(mut self, exclude: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude = exclude.into_iter().map(Into::into).collect();
        self
    }

    pub fn mirror(mut self, mirror: impl Into<String>) -> Self {
        self.mirror = Some(mirror.into());
        self
    }

    pub fn foreign(mut self, foreign: bool) -> Self {
        self.foreign = foreign;
        self
    }

    pub fn merged_usr(mut self, merged_usr: bool) -> Self {
        self.merged_usr = Some(merged_usr);
        self
    }

    pub fn no_resolve_deps(mut self, no_resolve_deps: bool) -> Self {
        self.no_resolve_deps = no_resolve_deps;
        self
    }

    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn print_debs(mut self, print_debs: bool) -> Self {
        self.print_debs = print_debs;
        self
    }

    pub fn privilege(mut self, privilege: Privilege) -> Self {
        self.privilege = privilege;
        self
    }

    pub fn build(self) -> DebootstrapConfig {
        DebootstrapConfig {
            suite: self.suite,
            target: self.target,
            variant: self.variant,
            arch: self.arch,
            components: self.components,
            include: self.include,
            exclude: self.exclude,
            mirror: self.mirror,
            foreign: self.foreign,
            merged_usr: self.merged_usr,
            no_resolve_deps: self.no_resolve_deps,
            verbose: self.verbose,
            print_debs: self.print_debs,
            privilege: self.privilege,
        }
    }
}

/// Test helper to create a DebootstrapConfig with minimal required fields.
///
/// All optional fields are initialized with their default values.
pub fn create_debootstrap(
    suite: impl Into<String>,
    target: impl Into<String>,
) -> DebootstrapConfig {
    DebootstrapConfigBuilder::new(suite, target).build()
}

/// Extracts MmdebstrapConfig from a Profile, returning `None` if it's not the mmdebstrap backend.
pub fn get_mmdebstrap_config(profile: &Profile) -> Option<&MmdebstrapConfig> {
    match &profile.bootstrap {
        Bootstrap::Mmdebstrap(cfg) => Some(cfg),
        _ => None,
    }
}

/// Extracts DebootstrapConfig from a Profile, returning `None` if it's not the debootstrap backend.
pub fn get_debootstrap_config(profile: &Profile) -> Option<&DebootstrapConfig> {
    match &profile.bootstrap {
        Bootstrap::Debootstrap(cfg) => Some(cfg),
        _ => None,
    }
}

/// Loads a Profile from YAML content in a temporary file.
pub fn load_profile_from_yaml(yaml: impl AsRef<str>) -> Result<Profile> {
    let yaml = yaml.as_ref();
    let mut file = NamedTempFile::new()?;
    file.write_all(yaml.as_bytes())?;
    if !yaml.ends_with('\n') {
        writeln!(file)?;
    }
    let path = Utf8Path::from_path(file.path()).expect("temp file path should be valid");
    Ok(load_profile(path)?)
}

/// Loads a Profile from YAML content, returning typed `RsdebstrapError`.
pub fn load_profile_from_yaml_typed(
    yaml: impl AsRef<str>,
) -> std::result::Result<Profile, RsdebstrapError> {
    let yaml = yaml.as_ref();
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    file.write_all(yaml.as_bytes())
        .expect("failed to write yaml");
    if !yaml.ends_with('\n') {
        writeln!(file).expect("failed to write trailing newline");
    }
    let path = Utf8Path::from_path(file.path()).expect("temp file path should be valid");
    load_profile(path)
}

/// RAII guard that restores the current working directory when dropped.
///
/// This guard saves the current directory on creation and automatically
/// restores it when it goes out of scope, even if a panic occurs.
pub struct CwdGuard {
    original: Utf8PathBuf,
}

impl CwdGuard {
    /// Creates a new CwdGuard, saving the current working directory.
    ///
    /// # Errors
    /// Returns an error if the current directory cannot be determined.
    pub fn new() -> Result<Self> {
        let original = std::env::current_dir()?;
        let original = Utf8PathBuf::from_path_buf(original).map_err(|path| {
            anyhow::anyhow!("current directory path is not valid UTF-8: {}", path.display())
        })?;
        Ok(Self { original })
    }

    /// Changes the current working directory to the specified path.
    ///
    /// # Errors
    /// Returns an error if the directory change fails.
    pub fn change_to(&self, path: &std::path::Path) -> Result<()> {
        std::env::set_current_dir(path)
            .with_context(|| format!("failed to change directory to {}", path.display()))
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        // Best effort to restore - log warning if it fails for debugging
        if let Err(err) = std::env::set_current_dir(&self.original) {
            warn!(
                original = %self.original,
                error = %err,
                "failed to restore working directory"
            );
        }
    }
}

/// Mock isolation context for testing task execution.
pub struct MockContext {
    rootfs: Utf8PathBuf,
    dry_run: bool,
    should_fail: bool,
    exit_code: Option<i32>,
    should_error: bool,
    error_message: Option<String>,
    executed_commands: RefCell<Vec<Vec<OsString>>>,
    executed_privileges: RefCell<Vec<Option<rsdebstrap::privilege::PrivilegeMethod>>>,
    return_no_status: bool,
}

impl MockContext {
    pub fn new(rootfs: &Utf8Path) -> Self {
        Self {
            rootfs: rootfs.to_owned(),
            dry_run: false,
            should_fail: false,
            exit_code: None,
            should_error: false,
            error_message: None,
            executed_commands: RefCell::new(Vec::new()),
            executed_privileges: RefCell::new(Vec::new()),
            return_no_status: false,
        }
    }

    pub fn new_dry_run(rootfs: &Utf8Path) -> Self {
        Self {
            rootfs: rootfs.to_owned(),
            dry_run: true,
            should_fail: false,
            exit_code: None,
            should_error: false,
            error_message: None,
            executed_commands: RefCell::new(Vec::new()),
            executed_privileges: RefCell::new(Vec::new()),
            return_no_status: false,
        }
    }

    pub fn with_failure(rootfs: &Utf8Path, exit_code: i32) -> Self {
        Self {
            rootfs: rootfs.to_owned(),
            dry_run: false,
            should_fail: true,
            exit_code: Some(exit_code),
            should_error: false,
            error_message: None,
            executed_commands: RefCell::new(Vec::new()),
            executed_privileges: RefCell::new(Vec::new()),
            return_no_status: false,
        }
    }

    pub fn with_error(rootfs: &Utf8Path, message: &str) -> Self {
        Self {
            rootfs: rootfs.to_owned(),
            dry_run: false,
            should_fail: false,
            exit_code: None,
            should_error: true,
            error_message: Some(message.to_string()),
            executed_commands: RefCell::new(Vec::new()),
            executed_privileges: RefCell::new(Vec::new()),
            return_no_status: false,
        }
    }

    pub fn with_no_status(rootfs: &Utf8Path) -> Self {
        Self {
            rootfs: rootfs.to_owned(),
            dry_run: false,
            should_fail: false,
            exit_code: None,
            should_error: false,
            error_message: None,
            executed_commands: RefCell::new(Vec::new()),
            executed_privileges: RefCell::new(Vec::new()),
            return_no_status: true,
        }
    }

    pub fn executed_commands(&self) -> Vec<Vec<OsString>> {
        self.executed_commands.borrow().clone()
    }

    pub fn executed_privileges(&self) -> Vec<Option<rsdebstrap::privilege::PrivilegeMethod>> {
        self.executed_privileges.borrow().clone()
    }
}

impl IsolationContext for MockContext {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn rootfs(&self) -> &Utf8Path {
        &self.rootfs
    }

    fn dry_run(&self) -> bool {
        self.dry_run
    }

    fn execute(
        &self,
        command: &[OsString],
        privilege: Option<rsdebstrap::privilege::PrivilegeMethod>,
    ) -> Result<ExecutionResult> {
        self.executed_commands.borrow_mut().push(command.to_vec());
        self.executed_privileges.borrow_mut().push(privilege);

        if self.should_error {
            anyhow::bail!("{}", self.error_message.as_deref().unwrap_or("mock error"));
        }

        if self.return_no_status {
            Ok(ExecutionResult { status: None })
        } else if self.should_fail {
            let status = Some(ExitStatus::from_raw(self.exit_code.unwrap_or(1) << 8));
            Ok(ExecutionResult { status })
        } else {
            Ok(ExecutionResult {
                status: Some(ExitStatus::from_raw(0)),
            })
        }
    }

    fn teardown(&mut self) -> Result<()> {
        Ok(())
    }
}
