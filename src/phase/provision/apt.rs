//! apt task implementation for the provision phase.
//!
//! This module provides the [`AptGetTask`] data structure, which runs `apt-get update`
//! and/or `apt-get install` inside the isolation context. Unlike a shell task the program
//! is fixed and the argv is built from validated package specs, so a profile cannot pass
//! an option to `apt-get` through a package name.

use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::Deserialize;
use tracing::info;

use crate::error::RsdebstrapError;
use crate::isolation::{IsolationContext, TaskIsolation};
use crate::privilege::{Privilege, PrivilegeMethod};

/// apt task data and execution logic.
///
/// Runs `apt-get update` (when `update` is set) and then `apt-get install` for the listed
/// packages. Used as a variant in the `ProvisionTask` enum for compile-time dispatch.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AptGetTask {
    /// Run `apt-get update` before installing. Defaults to `false`, so that splitting
    /// installs over several apt tasks does not refresh the package lists each time; set
    /// it on the first apt task, since a freshly bootstrapped rootfs has no package lists.
    #[serde(default)]
    update: bool,

    /// Packages to install with `apt-get install`. Each entry is a package name, optionally
    /// followed by `:<arch>`, and then optionally by `=<version>` or `/<release>`.
    #[serde(
        default,
        deserialize_with = "crate::de::string_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schemars(with = "Option<Vec<String>>")]
    install: Vec<String>,

    /// Install recommended packages too. Defaults to `false`
    /// (`--no-install-recommends`).
    #[serde(default)]
    recommends: bool,

    /// Privilege escalation setting as declared in the profile.
    #[serde(default)]
    privilege: Privilege,

    /// Isolation setting as declared in the profile. `false` is rejected: it would run the
    /// host's `apt-get` against the host.
    #[serde(default)]
    isolation: TaskIsolation,
}

impl AptGetTask {
    /// Creates a task that runs `apt-get update` (if `update`) and then installs `install`.
    ///
    /// Note: Call [`validate()`](Self::validate) after construction to check the package
    /// specs.
    pub fn new(update: bool, install: Vec<String>) -> Self {
        Self {
            update,
            install,
            recommends: false,
            privilege: Privilege::default(),
            isolation: TaskIsolation::default(),
        }
    }

    /// Returns a copy of this task that installs recommended packages as well.
    #[must_use]
    pub fn with_recommends(mut self, recommends: bool) -> Self {
        self.recommends = recommends;
        self
    }

    /// Returns whether this task runs `apt-get update`.
    pub fn update(&self) -> bool {
        self.update
    }

    /// Returns the packages this task installs.
    pub fn install(&self) -> &[String] {
        &self.install
    }

    /// Returns whether recommended packages are installed.
    pub fn recommends(&self) -> bool {
        self.recommends
    }

    /// Returns a human-readable name for this task (without type prefix).
    pub fn name(&self) -> &'static str {
        match (self.update, self.install.is_empty()) {
            (true, true) => "update",
            (true, false) => "update+install",
            (false, _) => "install",
        }
    }

    /// Returns the privilege setting as written in the profile.
    pub fn privilege(&self) -> &Privilege {
        &self.privilege
    }

    /// Returns the isolation setting as written in the profile.
    pub fn task_isolation(&self) -> &TaskIsolation {
        &self.isolation
    }

    /// Validates the task configuration.
    ///
    /// # Errors
    ///
    /// Returns `RsdebstrapError::Validation` if the task does nothing, declares
    /// `isolation: false`, or lists a package spec that is not a valid one.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        if !self.update && self.install.is_empty() {
            return Err(RsdebstrapError::Validation(
                "apt task must set `update: true` or list packages in `install`".to_string(),
            ));
        }
        if self.isolation == TaskIsolation::Disabled {
            return Err(RsdebstrapError::Validation(
                "apt task does not accept `isolation: false`: it would run the host's apt-get \
                against the host rather than the rootfs"
                    .to_string(),
            ));
        }
        for spec in &self.install {
            validate_package_spec(spec)?;
        }
        Ok(())
    }

    /// Runs the task using the provided isolation context.
    ///
    /// Callers should invoke [`validate()`](Self::validate) before this method.
    pub fn execute(
        &self,
        context: &dyn IsolationContext,
        privilege: Option<PrivilegeMethod>,
    ) -> Result<()> {
        if self.update {
            info!("running apt-get update (isolation: {})", context.name());
            run_apt_get(context, privilege, ["update"])?;
        }

        if !self.install.is_empty() {
            info!(
                "running apt-get install {} (isolation: {})",
                self.install.join(" "),
                context.name()
            );
            let mut args = vec!["install", "-y"];
            if !self.recommends {
                args.push("--no-install-recommends");
            }
            args.extend(self.install.iter().map(String::as_str));
            let result = run_apt_get(context, privilege, args);
            if !self.update {
                return result.context(
                    "apt-get install failed in a task without `update: true`; if no earlier \
                    task ran `apt-get update`, the rootfs has no package lists to install from",
                );
            }
            result?;
        }

        info!("apt task completed successfully");
        Ok(())
    }
}

// `DEBIAN_FRONTEND` travels in the argv through `env` because the privilege escalation in
// front of `chroot` resets the environment. A conffile prompt is dpkg's own rather than
// debconf's, so the frontend alone does not keep it from waiting on a stdin nobody writes
// to; `--force-confdef`/`--force-confold` answer it, keeping a file an earlier task edited.
fn apt_get_command<'a>(args: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    [
        "/usr/bin/env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "-o",
        "Dpkg::Options::=--force-confdef",
        "-o",
        "Dpkg::Options::=--force-confold",
    ]
    .into_iter()
    .chain(args)
    .map(str::to_string)
    .collect()
}

fn run_apt_get<'a>(
    context: &dyn IsolationContext,
    privilege: Option<PrivilegeMethod>,
    args: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let command = apt_get_command(args);
    let result = crate::phase::execute_in_context(context, &command, "apt-get", privilege)?;
    crate::phase::check_execution_result(&result, &command, context.name(), context.dry_run())
}

/// Refuses anything but `name[:arch][=version|/release]`.
///
/// The point is the first character: a spec starting with `-` would reach `apt-get` as an
/// option. The rest follows Debian policy for names and versions so that a typo fails at
/// load time rather than after the bootstrap. A trailing `-` is refused too, because
/// `apt-get install foo-` *removes* `foo` when no package is named `foo-`.
fn validate_package_spec(spec: &str) -> Result<(), RsdebstrapError> {
    let invalid = |why: &str| {
        RsdebstrapError::Validation(format!(
            "apt install entry {:?} is not a package spec ({}); expected \
            name[:arch][=version|/release]",
            spec, why
        ))
    };

    let (head, suffix) = match spec.find(['=', '/']) {
        Some(i) => (&spec[..i], Some((&spec[i..i + 1], &spec[i + 1..]))),
        None => (spec, None),
    };
    let (name, arch) = match head.split_once(':') {
        Some((name, arch)) => (name, Some(arch)),
        None => (head, None),
    };

    let name_ok = name.len() >= 2
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.')
        });
    if !name_ok {
        return Err(invalid(
            "a name is at least two characters of a-z, 0-9, '+', '-' and '.', \
            starting with a letter or digit",
        ));
    }
    if name.ends_with('-') {
        return Err(invalid("a trailing '-' asks apt-get to remove the package"));
    }

    if let Some(arch) = arch
        && (arch.is_empty()
            || !arch
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
    {
        return Err(invalid("an architecture is a-z, 0-9 and '-'"));
    }

    match suffix {
        Some(("=", version))
            if version.is_empty()
                || !version.bytes().next().is_some_and(|b| b.is_ascii_digit())
                || !version.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~' | b':' | b'-')
                }) =>
        {
            Err(invalid(
                "a version starts with a digit and is A-Z, a-z, 0-9, '.', '+', '~', ':' and '-'",
            ))
        }
        Some(("/", release))
            if release.is_empty()
                || !release.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'_' | b'-')
                }) =>
        {
            Err(invalid("a release is A-Z, a-z, 0-9, '.', '+', '_' and '-'"))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_spec_acceptance_set() {
        for (spec, accepted) in [
            ("docker-ce", true),
            ("g++", true),
            ("libc6:amd64", true),
            ("linux-image-amd64/trixie-backports", true),
            ("nginx=1.26.0-1", true),
            ("docker-ce=5:27.3.1-1~debian.12~bookworm", true),
            ("libc6:i386=2.36-9", true),
            ("0ad", true),
            ("", false),
            ("a", false),
            ("-o", false),
            ("--allow-unauthenticated", false),
            ("Docker", false),
            ("foo-", false),
            ("foo bar", false),
            ("foo*", false),
            ("foo:", false),
            ("foo=", false),
            ("foo=abc", false),
            ("foo/", false),
            ("foo/bar/baz", false),
            ("foo=1.0/trixie", false),
            (":amd64", false),
        ] {
            let got = validate_package_spec(spec).is_ok();
            assert_eq!(got, accepted, "{spec:?}: accepted = {got}, expected {accepted}");
        }
    }

    #[test]
    fn apt_get_command_puts_options_before_the_action() {
        assert_eq!(
            apt_get_command(["install", "-y", "curl"]),
            [
                "/usr/bin/env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                "install",
                "-y",
                "curl",
            ]
        );
    }
}
