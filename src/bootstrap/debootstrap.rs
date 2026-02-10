//! debootstrap backend implementation.

use super::{BootstrapBackend, CommandArgsBuilder, FlagValueStyle, RootfsOutput};
use crate::privilege::Privilege;
use anyhow::Result;
use camino::Utf8Path;
use serde::{Deserialize, Serialize};
use strum::Display;

/// Variant defines the package selection strategy for debootstrap
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
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
    /// Use merged /usr directory structure
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
    /// Privilege escalation setting
    #[serde(default)]
    pub privilege: Privilege,
}

impl BootstrapBackend for DebootstrapConfig {
    fn command_name(&self) -> &str {
        "debootstrap"
    }

    #[tracing::instrument(skip(self, output_dir))]
    fn build_args(&self, output_dir: &Utf8Path) -> Result<Vec<String>> {
        let mut builder = CommandArgsBuilder::new();

        // Add options
        if let Some(ref arch) = self.arch {
            builder.push_flag_value("--arch", arch, FlagValueStyle::Equals);
        }

        // Only add --variant if it's not the default (Minbase)
        builder.push_if_not_default("--variant", &self.variant, FlagValueStyle::Equals);

        builder.push_comma_joined("--components", &self.components, FlagValueStyle::Equals);
        builder.push_comma_joined("--include", &self.include, FlagValueStyle::Equals);
        builder.push_comma_joined("--exclude", &self.exclude, FlagValueStyle::Equals);

        if self.foreign {
            builder.push_flag("--foreign");
        }

        match self.merged_usr {
            Some(true) => builder.push_flag("--merged-usr"),
            Some(false) => builder.push_flag("--no-merged-usr"),
            None => {}
        }

        if self.no_resolve_deps {
            builder.push_flag("--no-resolve-deps");
        }

        if self.verbose {
            builder.push_flag("--verbose");
        }

        if self.print_debs {
            builder.push_flag("--print-debs");
        }

        // Add positional arguments: SUITE TARGET [MIRROR]
        builder.push_arg(self.suite.clone());

        let target_path = output_dir.join(&self.target);
        builder.push_arg(target_path.to_string());

        let mut cmd_args = builder.into_args();

        if let Some(ref mirror) = self.mirror
            && !mirror.trim().is_empty()
        {
            cmd_args.push(mirror.clone());
        }

        self.log_command_args(&cmd_args);

        Ok(cmd_args)
    }

    fn rootfs_output(&self, output_dir: &Utf8Path) -> Result<RootfsOutput> {
        Ok(RootfsOutput::Directory(output_dir.join(&self.target)))
    }
}
