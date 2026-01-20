use anyhow::Result;
use camino::{Utf8Path, Utf8PathBuf};
use rsdebstrap::backends::debootstrap::DebootstrapConfig;
use rsdebstrap::backends::mmdebstrap::MmdebstrapConfig;
use rsdebstrap::config::{Bootstrap, Profile, load_profile};
use std::io::Write;
use std::sync::{LazyLock, Mutex};
use tempfile::NamedTempFile;
use tracing::warn;

/// Global mutex to serialize tests that modify the current working directory.
/// This prevents parallel tests from interfering with each other.
#[allow(dead_code)]
pub static CWD_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[macro_export]
macro_rules! yaml {
    ($content:literal) => {
        $crate::helpers::dedent($content)
    };
}

#[allow(dead_code)]
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

/// Minimal mmdebstrap profile YAML fixture (for future tests).
#[allow(dead_code)]
pub fn yaml_profile_mmdebstrap_minimal() -> String {
    // editorconfig-checker-disable
    dedent(
        r#"---
dir: /tmp/test
bootstrap:
  type: mmdebstrap
  suite: bookworm
  target: rootfs.tar.zst
"#,
    )
    // editorconfig-checker-enable
}

/// Minimal debootstrap profile YAML fixture (for future tests).
#[allow(dead_code)]
pub fn yaml_profile_debootstrap_minimal() -> String {
    // editorconfig-checker-disable
    dedent(
        r#"---
dir: /tmp/test
bootstrap:
  type: debootstrap
  suite: bookworm
  target: rootfs
"#,
    )
    // editorconfig-checker-enable
}

/// Test helper to create a MmdebstrapConfig with minimal required fields.
///
/// All optional fields are initialized with their default values.
#[allow(dead_code)]
pub fn create_mmdebstrap(suite: impl Into<String>, target: impl Into<String>) -> MmdebstrapConfig {
    MmdebstrapConfig {
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
    }
}

/// Test helper to create a DebootstrapConfig with minimal required fields.
///
/// All optional fields are initialized with their default values.
#[allow(dead_code)]
pub fn create_debootstrap(
    suite: impl Into<String>,
    target: impl Into<String>,
) -> DebootstrapConfig {
    DebootstrapConfig {
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
    }
}

/// Extracts MmdebstrapConfig from a Profile, panicking if it's not the mmdebstrap backend.
///
/// # Panics
/// Panics if the profile's bootstrap type is not mmdebstrap.
#[allow(dead_code)]
pub fn get_mmdebstrap_config(profile: &Profile) -> &MmdebstrapConfig {
    if let Bootstrap::Mmdebstrap(cfg) = &profile.bootstrap {
        cfg
    } else {
        panic!("Expected mmdebstrap bootstrap type");
    }
}

/// Extracts DebootstrapConfig from a Profile, panicking if it's not the debootstrap backend.
///
/// # Panics
/// Panics if the profile's bootstrap type is not debootstrap.
#[allow(dead_code)]
pub fn get_debootstrap_config(profile: &Profile) -> &DebootstrapConfig {
    if let Bootstrap::Debootstrap(cfg) = &profile.bootstrap {
        cfg
    } else {
        panic!("Expected debootstrap bootstrap type");
    }
}

/// Loads a Profile from YAML content in a temporary file.
#[allow(dead_code)]
pub fn load_profile_from_yaml(yaml: impl AsRef<str>) -> Result<Profile> {
    let yaml = yaml.as_ref();
    let mut file = NamedTempFile::new()?;
    file.write_all(yaml.as_bytes())?;
    if !yaml.ends_with('\n') {
        writeln!(file)?;
    }
    let path = Utf8Path::from_path(file.path()).expect("temp file path should be valid");
    load_profile(path)
}

/// RAII guard that restores the current working directory when dropped.
///
/// This guard saves the current directory on creation and automatically
/// restores it when it goes out of scope, even if a panic occurs.
#[allow(dead_code)]
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
            anyhow::anyhow!(
                "current directory path is not valid UTF-8: {}",
                path.display()
            )
        })?;
        Ok(Self { original })
    }

    /// Changes the current working directory to the specified path.
    ///
    /// # Errors
    /// Returns an error if the directory change fails.
    pub fn change_to(&self, path: &std::path::Path) -> Result<()> {
        std::env::set_current_dir(path)?;
        Ok(())
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
