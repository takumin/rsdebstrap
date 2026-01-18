//! debootstrap backend implementation.

use super::BootstrapBackend;
use anyhow::Result;
use camino::Utf8Path;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fmt;
use tracing::debug;

/// Variant defines the package selection strategy for debootstrap
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Variant {
    /// Minimal base system (default)
    #[serde(alias = "")]
    #[default]
    Minbase,
    /// Build environment with build-essential
    Buildd,
    /// Fakechroot variant
    Fakechroot,
    /// Scratchbox variant
    Scratchbox,
}

impl fmt::Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Variant::Minbase => write!(f, "minbase"),
            Variant::Buildd => write!(f, "buildd"),
            Variant::Fakechroot => write!(f, "fakechroot"),
            Variant::Scratchbox => write!(f, "scratchbox"),
        }
    }
}

/// Configuration for debootstrap operations.
///
/// This structure contains all settings needed to customize the Debian
/// bootstrapping process using debootstrap.
#[derive(Debug, Deserialize)]
pub struct DebootstrapConfig {
    /// Debian suite name (e.g., "bookworm", "trixie")
    pub suite: String,
    /// Target output directory path (relative to profile dir)
    pub target: String,
    /// Package selection variant (defaults to Minbase)
    #[serde(default)]
    pub variant: Variant,
    /// Target architecture (e.g., "amd64", "arm64")
    #[serde(default)]
    pub arch: Option<String>,
    /// Repository components to enable (e.g., "main", "contrib", "non-free")
    #[serde(default)]
    pub components: Vec<String>,
    /// Additional packages to include
    #[serde(default)]
    pub include: Vec<String>,
    /// Packages to exclude
    #[serde(default)]
    pub exclude: Vec<String>,
    /// APT mirror URL to use as package source
    #[serde(default)]
    pub mirror: Option<String>,
    /// Perform two-stage bootstrap (for cross-architecture installations)
    #[serde(default)]
    pub foreign: bool,
    /// Use merged /usr directory structure (None = don't specify, Some(true) = --merged-usr, Some(false) = --no-merged-usr)
    #[serde(default)]
    pub merged_usr: Option<bool>,
    /// Don't resolve recommends/suggests
    #[serde(default)]
    pub no_resolve_deps: bool,
    /// Verbose output
    #[serde(default)]
    pub verbose: bool,
    /// Print packages to be installed and exit
    #[serde(default)]
    pub print_debs: bool,
}

/// Adds a flag to the command arguments.
fn add_simple_flag(cmd_args: &mut Vec<OsString>, flag: &str) {
    cmd_args.push(flag.into());
}

/// Adds a flag with value to the command arguments if the value is not empty.
fn add_flag(cmd_args: &mut Vec<OsString>, flag: &str, value: &str) {
    if !value.is_empty() {
        cmd_args.push(format!("{}={}", flag, value).into());
    }
}

impl BootstrapBackend for DebootstrapConfig {
    fn command_name(&self) -> &str {
        "debootstrap"
    }

    #[tracing::instrument(skip(self, output_dir))]
    fn build_args(&self, output_dir: &Utf8Path) -> Result<Vec<OsString>> {
        let mut cmd_args = Vec::<OsString>::new();

        // Add options
        if let Some(ref arch) = self.arch {
            add_flag(&mut cmd_args, "--arch", arch);
        }

        add_flag(&mut cmd_args, "--variant", &self.variant.to_string());

        if !self.components.is_empty() {
            add_flag(&mut cmd_args, "--components", &self.components.join(","));
        }

        if !self.include.is_empty() {
            add_flag(&mut cmd_args, "--include", &self.include.join(","));
        }

        if !self.exclude.is_empty() {
            add_flag(&mut cmd_args, "--exclude", &self.exclude.join(","));
        }

        if self.foreign {
            add_simple_flag(&mut cmd_args, "--foreign");
        }

        match self.merged_usr {
            Some(true) => add_simple_flag(&mut cmd_args, "--merged-usr"),
            Some(false) => add_simple_flag(&mut cmd_args, "--no-merged-usr"),
            None => {}
        }

        if self.no_resolve_deps {
            add_simple_flag(&mut cmd_args, "--no-resolve-deps");
        }

        if self.verbose {
            add_simple_flag(&mut cmd_args, "--verbose");
        }

        if self.print_debs {
            add_simple_flag(&mut cmd_args, "--print-debs");
        }

        // Add positional arguments: SUITE TARGET [MIRROR]
        cmd_args.push(self.suite.clone().into());

        let target_path = output_dir.join(&self.target);
        cmd_args.push(target_path.into_os_string());

        if let Some(ref mirror) = self.mirror {
            if !mirror.trim().is_empty() {
                cmd_args.push(mirror.into());
            }
        }

        debug!(
            "debootstrap would run: debootstrap {}",
            cmd_args
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );

        Ok(cmd_args)
    }
}
