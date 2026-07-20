pub mod bootstrap;
pub mod cli;
pub mod config;
pub(crate) mod de;
pub mod error;
pub mod executor;
pub mod isolation;
pub mod phase;
pub mod pipeline;
pub mod privilege;
#[cfg(feature = "schema")]
pub mod schema;

pub use error::RsdebstrapError;

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use camino::Utf8Path;
#[cfg(feature = "schema")]
use serde::Serialize;
use tracing::{info, warn};
use tracing_subscriber::{FmtSubscriber, filter::LevelFilter};

use crate::executor::CommandExecutor;
use crate::isolation::mount::RootfsMounts;
use crate::isolation::resolv_conf::RootfsResolvConf;

pub fn init_logging(log_level: cli::LogLevel) -> Result<()> {
    let filter = match log_level {
        cli::LogLevel::Trace => LevelFilter::TRACE,
        cli::LogLevel::Debug => LevelFilter::DEBUG,
        cli::LogLevel::Info => LevelFilter::INFO,
        cli::LogLevel::Warn => LevelFilter::WARN,
        cli::LogLevel::Error => LevelFilter::ERROR,
    };

    tracing::subscriber::set_global_default(
        FmtSubscriber::builder().with_max_level(filter).finish(),
    )
    .context("failed to set global default tracing subscriber")
}

/// Executes the bootstrap phase using the configured backend.
fn run_bootstrap_phase(
    profile: &config::Profile,
    executor: &Arc<dyn CommandExecutor>,
) -> Result<()> {
    let backend = profile.bootstrap.as_backend();
    let command_name = backend.command_name();

    let args = backend
        .build_args(&profile.dir)
        .with_context(|| format!("failed to build arguments for {}", command_name))?;

    let privilege = profile.bootstrap.resolved_privilege_method();
    let spec = executor::CommandSpec::new(command_name, args).with_privilege(privilege);
    executor
        .execute_checked(&spec)
        .with_context(|| format!("failed to execute {}", command_name))?;

    Ok(())
}

/// Executes the pipeline phase (prepare, provision, assemble).
fn run_pipeline_phase(
    profile: &config::Profile,
    executor: Arc<dyn CommandExecutor>,
    dry_run: bool,
) -> Result<()> {
    let pipeline = profile.pipeline();

    if pipeline.is_empty() {
        return Ok(());
    }

    // Get rootfs directory (validation ensures it's a directory if tasks exist)
    let backend = profile.bootstrap.as_backend();
    let bootstrap::RootfsOutput::Directory(rootfs) = backend.rootfs_output(&profile.dir)? else {
        return Err(RsdebstrapError::Validation(
            "pipeline tasks require directory output but bootstrap is configured for \
            non-directory format. Please set bootstrap format to 'directory' or remove \
            pipeline tasks."
                .to_string(),
        )
        .into());
    };

    // Set up filesystem mounts (if configured in prepare phase)
    let mount_entries = profile
        .prepare
        .mount
        .as_ref()
        .map(|m| m.resolved_mounts())
        .unwrap_or_default();
    let privilege = profile.defaults.privilege.as_ref().map(|d| d.method);
    let mut mounts =
        RootfsMounts::new(&rootfs, mount_entries, executor.clone(), privilege, dry_run);
    mounts
        .mount()
        .context("failed to mount filesystems in rootfs")?;

    // Set up resolv.conf (if configured in prepare phase)
    // setup failure is handled by Drop guards for mounts cleanup
    let resolv_conf_config = profile.prepare.resolv_conf.as_ref().map(|rc| rc.config());
    let mut resolv_conf = RootfsResolvConf::new(
        &rootfs,
        resolv_conf_config,
        Utf8Path::new("/etc/resolv.conf"),
        executor.clone(),
        privilege,
        dry_run,
    );
    resolv_conf
        .setup()
        .context("failed to set up resolv.conf in rootfs")?;

    // Run prepare + provision, then restore the original resolv.conf BEFORE
    // the assemble phase: an assemble resolv_conf task writes the permanent
    // /etc/resolv.conf, which teardown's `rm -f` + backup restore would
    // otherwise destroy. Assemble is gated on both prior stages succeeding:
    // after a failed teardown the guard's Drop backstop retries the restore
    // at scope end and would clobber assemble's output. Unmount always runs
    // last (mounts bracket all three phases).
    // Error priority: prepare/provision > resolv_conf restore > assemble > unmount.
    let run_result = pipeline.run_prepare_and_provision(&rootfs, &executor, dry_run);
    let resolv_result = resolv_conf.teardown();
    let assemble_result = if run_result.is_ok() && resolv_result.is_ok() {
        pipeline.run_assemble(&rootfs, &executor, dry_run)
    } else {
        Ok(())
    };
    let unmount_result = mounts.unmount();

    if let Err(e) = run_result {
        if let Err(r) = resolv_result {
            tracing::error!("resolv.conf restore also failed: {:#}", r);
        }
        if let Err(u) = unmount_result {
            tracing::error!(
                "unmount also failed after pipeline error: {:#}. \
                Drop guard will attempt cleanup.",
                u
            );
        }
        return Err(e);
    }

    if let Err(e) = resolv_result {
        if let Err(u) = unmount_result {
            tracing::error!(
                "unmount also failed after resolv.conf restore error: {:#}. \
                Drop guard will attempt cleanup.",
                u
            );
        }
        return Err(e)
            .context("failed to restore resolv.conf after provisioning; assemble phase skipped");
    }

    if let Err(e) = assemble_result {
        if let Err(u) = unmount_result {
            tracing::error!(
                "unmount also failed after assemble error: {:#}. \
                Drop guard will attempt cleanup.",
                u
            );
        }
        return Err(e);
    }

    unmount_result.context("failed to unmount filesystems after pipeline completed successfully")
}

pub fn run_apply(opts: &cli::ApplyArgs, executor: Arc<dyn CommandExecutor>) -> Result<()> {
    if opts.dry_run {
        warn!("DRY-RUN MODE: No changes will be made");
    }

    let profile = config::load_profile(opts.common.file.as_path())
        .with_context(|| format!("failed to load profile from {}", opts.common.file))?;
    profile.validate().context("profile validation failed")?;

    if !opts.dry_run && !profile.dir.exists() {
        fs::create_dir_all(&profile.dir)
            .with_context(|| format!("failed to create directory: {}", profile.dir))?;
    }

    run_bootstrap_phase(&profile, &executor)?;
    run_pipeline_phase(&profile, executor, opts.dry_run)?;

    Ok(())
}

pub fn run_validate(opts: &cli::ValidateArgs) -> Result<()> {
    let profile = config::load_profile(opts.common.file.as_path())
        .with_context(|| format!("failed to load profile from {}", opts.common.file))?;
    profile.validate().context("profile validation failed")?;
    info!("validation successful:\n{:#?}", profile);
    Ok(())
}

/// Generates the JSON Schema for the YAML profile format.
///
/// The schema is derived directly from the [`config::Profile`] Rust types, so it always
/// tracks what `apply`/`validate` accept — there is no separately maintained schema to
/// drift out of sync.
#[cfg(feature = "schema")]
pub fn profile_json_schema() -> serde_json::Value {
    // `schemars::Schema` wraps a `serde_json::Value`; `to_value` unwraps it infallibly,
    // avoiding a redundant serialize round-trip over the whole schema tree.
    schemars::schema_for!(config::Profile).to_value()
}

/// Canonical pretty-printed rendering of the profile JSON Schema (no trailing newline).
///
/// Uses tab indentation rather than `serde_json::to_string_pretty`'s hard-coded two spaces,
/// matching the repository's JSON convention (e.g. `.renovaterc.json`, `.claude/settings.json`)
/// and `.editorconfig`'s `[*] indent_style = tab`. Both the `schema` subcommand and the
/// committed-schema drift test render through this function so they cannot diverge.
#[cfg(feature = "schema")]
pub fn profile_json_schema_pretty() -> String {
    let value = profile_json_schema();
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"\t");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    value
        .serialize(&mut ser)
        .expect("Profile JSON Schema must serialize");
    String::from_utf8(buf).expect("serde_json emits valid UTF-8")
}

/// Prints the profile JSON Schema (pretty-printed) to stdout.
///
/// A closed stdout (e.g. `rsdebstrap schema | head`) is a normal way for a pipe
/// consumer to stop reading, so `BrokenPipe` ends the command successfully instead
/// of panicking the way `println!` would once the schema outgrows the pipe buffer.
#[cfg(feature = "schema")]
pub fn run_schema() -> Result<()> {
    use std::io::Write;

    let mut stdout = std::io::stdout().lock();
    let result = stdout
        .write_all(profile_json_schema_pretty().as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush());
    match result {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other
            .map_err(|e| RsdebstrapError::io("failed to write the profile JSON Schema", e).into()),
    }
}

#[cfg(test)]
mod tests {
    //! Sequencing tests for `run_pipeline_phase()`: the temporary prepare
    //! resolv.conf must be restored after provision and before assemble, so an
    //! assemble resolv_conf task's permanent file/symlink survives, and the
    //! assemble phase must be gated on that restore succeeding.

    use super::*;
    use crate::executor::{CommandSpec, ExecutionResult};
    use camino::Utf8PathBuf;
    use std::io::Write as _;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::sync::Mutex;

    /// Records commands and really executes them so tests can assert both the
    /// command order and the actual filesystem effects on a temp rootfs.
    /// `fail_on_command` short-circuits a matching command with exit 1
    /// without executing it.
    struct RecordingExecutor {
        commands: Mutex<Vec<(String, Vec<String>)>>,
        fail_on_command: Mutex<Option<String>>,
    }

    impl RecordingExecutor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                commands: Mutex::new(Vec::new()),
                fail_on_command: Mutex::new(None),
            })
        }

        fn fail_on_command(&self, command: &str) {
            *self.fail_on_command.lock().unwrap() = Some(command.to_string());
        }

        fn command_names(&self) -> Vec<String> {
            self.commands
                .lock()
                .unwrap()
                .iter()
                .map(|(command, _)| command.clone())
                .collect()
        }
    }

    impl CommandExecutor for RecordingExecutor {
        fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
            self.commands
                .lock()
                .unwrap()
                .push((spec.command.clone(), spec.args.clone()));

            if self
                .fail_on_command
                .lock()
                .unwrap()
                .as_deref()
                .is_some_and(|command| command == spec.command)
            {
                return Ok(ExecutionResult {
                    status: Some(ExitStatus::from_raw(1 << 8)),
                });
            }

            let status = std::process::Command::new(&spec.command)
                .args(&spec.args)
                .status()?;
            Ok(ExecutionResult {
                status: Some(status),
            })
        }
    }

    /// Minimal profile: directory bootstrap output, no mounts, empty provision,
    /// no privilege defaults (commands run unprivileged so the executor can
    /// really run them).
    fn profile_yaml(dir: &Utf8Path, prepare: bool, assemble: bool) -> String {
        let mut yaml = format!(
            "dir: {dir}\nbootstrap:\n  type: mmdebstrap\n  suite: trixie\n  target: rootfs\n"
        );
        if prepare {
            yaml.push_str("prepare:\n  resolv_conf:\n    name_servers: [192.0.2.1]\n");
        }
        if assemble {
            yaml.push_str(
                "assemble:\n  resolv_conf:\n    link: ../run/systemd/resolve/stub-resolv.conf\n",
            );
        }
        yaml
    }

    fn load_profile_from(yaml: &str) -> config::Profile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();
        file.flush().unwrap();
        let profile = config::load_profile(Utf8Path::from_path(file.path()).unwrap()).unwrap();
        // load_profile does not validate; mirror run_apply, which validates next.
        profile.validate().unwrap();
        profile
    }

    fn seed_rootfs(dir: &Utf8Path) -> Utf8PathBuf {
        let rootfs = dir.join("rootfs");
        fs::create_dir_all(rootfs.join("etc")).unwrap();
        fs::write(rootfs.join("etc/resolv.conf"), "# original\n").unwrap();
        rootfs
    }

    const LINK_TARGET: &str = "../run/systemd/resolve/stub-resolv.conf";

    #[test]
    fn both_configured_assemble_output_survives() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, true));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        // setup (mv, cp, chmod) → teardown restore (rm, mv) → assemble (rm, ln):
        // the restore happens between provision and assemble, so the symlink wins.
        // Assemble's rm deleting the just-restored original is intended — the
        // permanent config replaces it.
        assert_eq!(executor.command_names(), ["mv", "cp", "chmod", "rm", "mv", "rm", "ln"]);
        let resolv = rootfs.join("etc/resolv.conf");
        assert!(
            fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&resolv).unwrap(), std::path::Path::new(LINK_TARGET));
        assert!(!rootfs.join("etc/resolv.conf.rsdebstrap-orig").exists());
    }

    #[test]
    fn prepare_only_restores_original() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, false));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        assert_eq!(executor.command_names(), ["mv", "cp", "chmod", "rm", "mv"]);
        let resolv = rootfs.join("etc/resolv.conf");
        assert!(fs::symlink_metadata(&resolv).unwrap().file_type().is_file());
        assert_eq!(fs::read_to_string(&resolv).unwrap(), "# original\n");
        assert!(!rootfs.join("etc/resolv.conf.rsdebstrap-orig").exists());
    }

    #[test]
    fn assemble_only_writes_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, false, true));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        // No mv: the prepare guard never activates, so nothing is backed up.
        assert_eq!(executor.command_names(), ["rm", "ln"]);
        let resolv = rootfs.join("etc/resolv.conf");
        assert!(
            fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&resolv).unwrap(), std::path::Path::new(LINK_TARGET));
        assert!(!rootfs.join("etc/resolv.conf.rsdebstrap-orig").exists());
    }

    #[test]
    fn empty_pipeline_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, false, false));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        assert!(executor.command_names().is_empty());
        let resolv = rootfs.join("etc/resolv.conf");
        assert_eq!(fs::read_to_string(&resolv).unwrap(), "# original\n");
    }

    #[test]
    fn teardown_failure_gates_assemble() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, true));
        let executor = RecordingExecutor::new();
        executor.fail_on_command("rm");

        let err = run_pipeline_phase(&profile, executor.clone(), false).unwrap_err();

        assert!(
            format!("{:#}", err).contains("failed to restore resolv.conf after provisioning"),
            "unexpected error: {err:#}"
        );
        // setup (mv, cp, chmod) → teardown rm fails → assemble is gated off
        // (no ln) → the guard's Drop backstop retries the teardown once more
        // (the second failing rm).
        assert_eq!(executor.command_names(), ["mv", "cp", "chmod", "rm", "rm"]);
        // The restore genuinely never happened: the temporary file and the
        // backup are still in place, and assemble never touched anything.
        let resolv = rootfs.join("etc/resolv.conf");
        assert_eq!(
            fs::read_to_string(&resolv).unwrap(),
            "# Generated by rsdebstrap\nnameserver 192.0.2.1\n"
        );
        assert!(rootfs.join("etc/resolv.conf.rsdebstrap-orig").exists());
    }

    #[test]
    fn setup_cp_failure_rolls_back_without_running_pipeline() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, true));
        let executor = RecordingExecutor::new();
        executor.fail_on_command("cp");

        let err = run_pipeline_phase(&profile, executor.clone(), false).unwrap_err();

        assert!(
            format!("{:#}", err).contains("failed to set up resolv.conf in rootfs"),
            "unexpected error: {err:#}"
        );
        // Backup mv, failed cp, rollback mv — the guard never activates, so
        // there is no Drop retry and neither pipeline stage runs.
        assert_eq!(executor.command_names(), ["mv", "cp", "mv"]);
        let resolv = rootfs.join("etc/resolv.conf");
        assert_eq!(fs::read_to_string(&resolv).unwrap(), "# original\n");
        assert!(!rootfs.join("etc/resolv.conf.rsdebstrap-orig").exists());
    }
}
