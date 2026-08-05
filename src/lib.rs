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
pub mod rootfs;
pub mod schema;

pub use error::RsdebstrapError;

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use camino::Utf8Path;
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
    let program = backend.program();
    let command_name = program.program_name();

    let args = backend
        .build_args(&profile.dir)
        .with_context(|| format!("failed to build arguments for {}", command_name))?;

    let privilege = profile.bootstrap.resolved_privilege_method();
    let spec = executor::CommandSpec::privileged(
        executor::PrivilegedProgram::Bootstrap(program),
        args,
        privilege,
    );
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
    run_pipeline_phase_with(profile, executor, None, dry_run)
}

/// [`run_pipeline_phase`] with the rootfs operations supplied rather than opened.
///
/// `ops` is `None` in production, where the privilege setting decides which
/// implementation to open. Tests pass one in to drive failure paths that used to
/// be reachable by making a `cp` or `mv` exit non-zero.
fn run_pipeline_phase_with(
    profile: &config::Profile,
    executor: Arc<dyn CommandExecutor>,
    ops: Option<Arc<dyn rootfs::RootfsOps>>,
    dry_run: bool,
) -> Result<()> {
    let pipeline = profile.pipeline();

    if pipeline.is_empty() {
        return Ok(());
    }

    // Profile validation has already rejected non-directory output when tasks
    // exist, so the error below is a defensive backstop.
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

    // Escalate once for the whole build: `rootfs::open` spawns a single helper
    // when privilege is configured, and every rootfs mutation from here on is a
    // typed request to it rather than its own `sudo` invocation.
    let ops = match ops {
        Some(ops) => ops,
        None => rootfs::open(&rootfs, privilege, dry_run)?,
    };

    // resolv.conf setup failure is handled by Drop guards for mounts cleanup.
    let resolv_conf_config = profile.prepare.resolv_conf.as_ref().map(|rc| rc.config());
    let mut resolv_conf = RootfsResolvConf::new(
        &rootfs,
        resolv_conf_config,
        Utf8Path::new("/etc/resolv.conf"),
        ops.clone(),
        dry_run,
    );
    resolv_conf
        .setup()
        .context("failed to set up resolv.conf in rootfs")?;

    // The ordering below is carried by `Provisioned`/`Restored`: assembly takes
    // a token only `restore` can produce, so it cannot run before the guard has
    // put the rootfs's own resolv.conf back — which matters because an assemble
    // resolv_conf task installs the permanent one, and a restore afterwards
    // would overwrite it. Mounts bracket everything, so unmount runs last.
    let restored = match pipeline.run_prepare_and_provision(&rootfs, &executor, &ops, dry_run) {
        Ok(provisioned) => resolv_conf.restore(provisioned).context(
            "failed to restore resolv.conf after provisioning; any assemble tasks were skipped",
        ),
        Err(run_err) => {
            // `Drop` would restore too, but only after the unmount below; the
            // restore belongs inside the mounted window.
            if let Err(restore_err) = resolv_conf.teardown() {
                tracing::error!("resolv.conf restore also failed: {:#}", restore_err);
            }
            Err(run_err)
        }
    };

    let assemble_result =
        restored.and_then(|token| pipeline.run_assemble(token, &rootfs, &executor, &ops, dry_run));
    let unmount_result = mounts.unmount();

    if let Err(e) = assemble_result {
        if let Err(u) = unmount_result {
            tracing::error!(
                "unmount also failed after pipeline error: {:#}. \
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
    // Sequencing tests for `run_pipeline_phase()`: the temporary prepare
    // resolv.conf must be restored after provision and before assemble, so an
    // assemble resolv_conf task's permanent file/symlink survives; the
    // assemble phase must be gated on prepare/provision and the restore both
    // succeeding; and an assemble failure must propagate while leaving the
    // restored original in place.

    use super::*;
    use crate::executor::{CommandSpec, ExecutionResult};
    use camino::Utf8PathBuf;
    use std::io::Write as _;
    use std::sync::Mutex;

    // Records commands and really executes them, so tests can assert both what
    // ran and the resulting filesystem state. Only provision tasks reach it now
    // — the resolv.conf lifecycle is syscalls through `RootfsOps`, and failures
    // there are injected with `FailingOps`.
    struct RecordingExecutor {
        commands: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl RecordingExecutor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                commands: Mutex::new(Vec::new()),
            })
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
                .push((spec.command().to_string(), spec.args().to_vec()));

            let status = std::process::Command::new(spec.command())
                .args(spec.args())
                .status()?;
            Ok(ExecutionResult {
                status: Some(status),
            })
        }
    }

    const LINK_ASSEMBLE: &str =
        "assemble:\n  resolv_conf:\n    link: ../run/systemd/resolve/stub-resolv.conf\n";
    const GENERATE_ASSEMBLE: &str = "assemble:\n  resolv_conf:\n    name_servers: [198.51.100.1]\n";

    // Minimal profile with a link-mode assemble task when `assemble` is set;
    // delegates to [`profile_yaml_with_assemble`].
    fn profile_yaml(
        dir: &Utf8Path,
        prepare: bool,
        provision: Option<&str>,
        assemble: bool,
    ) -> String {
        profile_yaml_with_assemble(dir, prepare, provision, assemble.then_some(LINK_ASSEMBLE))
    }

    // Minimal profile: directory bootstrap output, no mounts, no privilege
    // defaults (commands run unprivileged so the executor can really run
    // them). `provision` adds one shell task with the given inline content,
    // running directly on the host (`isolation: false`). `assemble`, if given,
    // is the raw YAML for the assemble section (e.g. [`LINK_ASSEMBLE`] or
    // [`GENERATE_ASSEMBLE`]).
    fn profile_yaml_with_assemble(
        dir: &Utf8Path,
        prepare: bool,
        provision: Option<&str>,
        assemble: Option<&str>,
    ) -> String {
        let mut yaml = format!(
            "dir: {dir}\nbootstrap:\n  type: mmdebstrap\n  suite: trixie\n  target: rootfs\n"
        );
        if prepare {
            yaml.push_str("prepare:\n  resolv_conf:\n    name_servers: [192.0.2.1]\n");
        }
        if let Some(content) = provision {
            // The content must stay quoted in the YAML: a bare `true` would
            // parse as a boolean, not a script string.
            yaml.push_str(&format!(
                "provision:\n  - type: shell\n    content: \"{content}\"\n    isolation: false\n"
            ));
        }
        if let Some(assemble_yaml) = assemble {
            yaml.push_str(assemble_yaml);
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
        // For shell provision tasks (DirectProvider): a real /tmp for the
        // staged script, and a /bin/sh resolving to the host shell so the
        // recording executor can really run it.
        fs::create_dir_all(rootfs.join("tmp")).unwrap();
        fs::create_dir_all(rootfs.join("bin")).unwrap();
        std::os::unix::fs::symlink("/bin/sh", rootfs.join("bin/sh")).unwrap();
        rootfs
    }

    const LINK_TARGET: &str = "../run/systemd/resolve/stub-resolv.conf";

    // Wraps real ops and fails one chosen operation. Replaces the old approach
    // of making a specific `cp`/`mv` argv exit non-zero: the rootfs mutations no
    // longer run as commands, so the failure has to be injected at this layer.
    struct FailingOps {
        inner: rootfs::LocalRootfsOps,
        fail: Failure,
        // Restores are the same call as installs, so a count distinguishes them.
        writes: std::sync::atomic::AtomicUsize,
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Failure {
        // Setup's install of the temporary resolv.conf.
        FirstWrite,
        // Teardown's restore of the original.
        SecondWrite,
        // Assemble's install of the permanent entry.
        Symlink,
        Remove,
    }

    impl FailingOps {
        fn boxed(rootfs: &Utf8Path, fail: Failure) -> Arc<dyn rootfs::RootfsOps> {
            Arc::new(Self {
                inner: rootfs::LocalRootfsOps::open(rootfs).unwrap(),
                fail,
                writes: std::sync::atomic::AtomicUsize::new(0),
            })
        }
    }

    fn refused(what: &str) -> RsdebstrapError {
        RsdebstrapError::Isolation(format!("{what} refused by the test"))
    }

    impl rootfs::RootfsOps for FailingOps {
        fn write_file(
            &self,
            path: &rootfs::RelPath,
            content: &[u8],
            mode: u32,
        ) -> std::result::Result<(), RsdebstrapError> {
            let nth = self
                .writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match (self.fail, nth) {
                (Failure::FirstWrite, 0) | (Failure::SecondWrite, 1) => Err(refused("write")),
                _ => self.inner.write_file(path, content, mode),
            }
        }

        fn write_symlink(
            &self,
            path: &rootfs::RelPath,
            target: &str,
        ) -> std::result::Result<(), RsdebstrapError> {
            if self.fail == Failure::Symlink {
                return Err(refused("symlink"));
            }
            self.inner.write_symlink(path, target)
        }

        fn import_file(
            &self,
            host_src: &Utf8Path,
            path: &rootfs::RelPath,
            mode: u32,
        ) -> std::result::Result<(), RsdebstrapError> {
            self.inner.import_file(host_src, path, mode)
        }

        fn remove(&self, path: &rootfs::RelPath) -> std::result::Result<(), RsdebstrapError> {
            if self.fail == Failure::Remove {
                return Err(refused("remove"));
            }
            self.inner.remove(path)
        }

        fn take(
            &self,
            path: &rootfs::RelPath,
        ) -> std::result::Result<Option<rootfs::TakenEntry>, RsdebstrapError> {
            self.inner.take(path)
        }
    }

    #[test]
    fn both_configured_assemble_output_survives() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, None, true));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        let resolv = rootfs.join("etc/resolv.conf");
        assert!(
            fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&resolv).unwrap(), std::path::Path::new(LINK_TARGET));
    }

    #[test]
    fn prepare_only_restores_original() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, None, false));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        let resolv = rootfs.join("etc/resolv.conf");
        assert!(fs::symlink_metadata(&resolv).unwrap().file_type().is_file());
        assert_eq!(fs::read_to_string(&resolv).unwrap(), "# original\n");
    }

    #[test]
    fn assemble_only_writes_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, false, None, true));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        let resolv = rootfs.join("etc/resolv.conf");
        assert!(
            fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&resolv).unwrap(), std::path::Path::new(LINK_TARGET));
    }

    #[test]
    fn empty_pipeline_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, false, None, false));
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
        let profile = load_profile_from(&profile_yaml(dir, true, None, true));
        let executor = RecordingExecutor::new();
        let ops = FailingOps::boxed(&rootfs, Failure::SecondWrite);

        let err =
            run_pipeline_phase_with(&profile, executor.clone(), Some(ops), false).unwrap_err();

        assert!(
            format!("{:#}", err).contains("failed to restore resolv.conf after provisioning"),
            "unexpected error: {err:#}"
        );
        // Assemble is gated off by the failed restore, but the guard's Drop
        // backstop retries it and succeeds, so the original still lands. The
        // original is held in memory, so a failed restore cannot lose it.
        let resolv = rootfs.join("etc/resolv.conf");
        assert_eq!(fs::read_to_string(&resolv).unwrap(), "# original\n");
        assert!(
            !executor.command_names().contains(&"ln".to_string()),
            "assemble ran despite the failed restore"
        );
    }

    #[test]
    fn setup_write_failure_rolls_back_without_running_pipeline() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, None, true));
        let executor = RecordingExecutor::new();
        let ops = FailingOps::boxed(&rootfs, Failure::FirstWrite);

        let err =
            run_pipeline_phase_with(&profile, executor.clone(), Some(ops), false).unwrap_err();

        assert!(
            format!("{:#}", err).contains("failed to set up resolv.conf in rootfs"),
            "unexpected error: {err:#}"
        );
        // The guard never activated, so neither pipeline stage ran and the
        // original is back exactly as it was found.
        assert!(executor.command_names().is_empty());
        let resolv = rootfs.join("etc/resolv.conf");
        assert_eq!(fs::read_to_string(&resolv).unwrap(), "# original\n");
    }

    #[test]
    fn restore_runs_after_provision_and_before_assemble() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, Some("true"), true));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        // The provision task is the only command; the resolv.conf lifecycle
        // around it is syscalls now. What the sequencing has to produce is the
        // assemble symlink surviving the restore that runs between the two.
        let sh = rootfs.join("bin/sh");
        assert_eq!(executor.command_names(), [sh.as_str()]);
        let resolv = rootfs.join("etc/resolv.conf");
        assert!(
            fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&resolv).unwrap(), std::path::Path::new(LINK_TARGET));
    }

    #[test]
    fn provision_failure_skips_assemble_and_restores_original() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, Some("exit 1"), true));
        let executor = RecordingExecutor::new();

        let err = run_pipeline_phase(&profile, executor.clone(), false).unwrap_err();

        assert!(
            format!("{:#}", err).contains("failed to run provision"),
            "unexpected error: {err:#}"
        );
        // The failed provision gates assemble off, but the teardown still
        // restores the original.
        let sh = rootfs.join("bin/sh");
        assert_eq!(executor.command_names(), [sh.as_str()], "assemble should not have run");
        let resolv = rootfs.join("etc/resolv.conf");
        assert!(fs::symlink_metadata(&resolv).unwrap().file_type().is_file());
        assert_eq!(fs::read_to_string(&resolv).unwrap(), "# original\n");
    }

    #[test]
    fn assemble_failure_propagates_and_preserves_restored_original() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, None, true));
        let executor = RecordingExecutor::new();
        // The assemble task installs a symlink, so failing that one operation
        // fails assemble while prepare's file writes still run for real.
        let ops = FailingOps::boxed(&rootfs, Failure::Symlink);

        let err =
            run_pipeline_phase_with(&profile, executor.clone(), Some(ops), false).unwrap_err();

        assert!(
            format!("{:#}", err).contains("failed to run assemble"),
            "unexpected error: {err:#}"
        );
        // The atomicity invariant: a failed assemble leaves the restored
        // original in place, and stages nothing where a later run would find it.
        let resolv = rootfs.join("etc/resolv.conf");
        assert!(fs::symlink_metadata(&resolv).unwrap().file_type().is_file());
        assert_eq!(fs::read_to_string(&resolv).unwrap(), "# original\n");
        let etc: Vec<String> = fs::read_dir(rootfs.join("etc"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(etc, ["resolv.conf"], "unexpected leftovers in /etc: {etc:?}");
    }

    // The old design moved the original to `<resolv>.rsdebstrap-orig`, so a
    // failed restore left it there: the rootfs ended with no /etc/resolv.conf
    // and an orphan file the operator had to move back by hand. The original is
    // now held in memory, so the failure mode this replaces cannot occur — a
    // restore that fails is retried by Drop, and nothing is left behind either
    // way.
    #[test]
    fn a_failed_restore_leaves_no_orphan_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, None, true));
        let executor = RecordingExecutor::new();
        let ops = FailingOps::boxed(&rootfs, Failure::SecondWrite);

        let err =
            run_pipeline_phase_with(&profile, executor.clone(), Some(ops), false).unwrap_err();

        assert!(
            format!("{:#}", err).contains("failed to restore resolv.conf after provisioning"),
            "unexpected error: {err:#}"
        );
        let etc: Vec<String> = fs::read_dir(rootfs.join("etc"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(etc, ["resolv.conf"], "unexpected leftovers in /etc: {etc:?}");
        assert_eq!(fs::read_to_string(rootfs.join("etc/resolv.conf")).unwrap(), "# original\n");
    }

    #[test]
    fn both_configured_generate_assemble_output_survives() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml_with_assemble(
            dir,
            true,
            None,
            Some(GENERATE_ASSEMBLE),
        ));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        // The generated file replaces the just-restored original.
        assert!(executor.command_names().is_empty(), "no command should have run");
        let resolv = rootfs.join("etc/resolv.conf");
        assert!(fs::symlink_metadata(&resolv).unwrap().file_type().is_file());
        assert!(
            fs::read_to_string(&resolv)
                .unwrap()
                .contains("nameserver 198.51.100.1")
        );
    }

    #[test]
    fn generate_assemble_only_writes_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml_with_assemble(
            dir,
            false,
            None,
            Some(GENERATE_ASSEMBLE),
        ));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        assert!(executor.command_names().is_empty(), "no command should have run");
        let resolv = rootfs.join("etc/resolv.conf");
        assert!(fs::symlink_metadata(&resolv).unwrap().file_type().is_file());
        assert!(
            fs::read_to_string(&resolv)
                .unwrap()
                .contains("nameserver 198.51.100.1")
        );
    }

    // Debian's default `/etc/resolv.conf` is a *symlink*, not a regular file,
    // yet every other pipeline-level test seeds a regular file. The prepare
    // guard must back the symlink up and restore it faithfully as a symlink
    // (the backup `mv` moves the link itself; the restore `mv` moves it back),
    // not flatten it into a regular file. Seed a *live* symlink whose relative
    // target sits in the same `/etc` directory so it still resolves after the
    // backup `mv`.
    #[test]
    fn prepare_only_restores_symlink_original() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let resolv = rootfs.join("etc/resolv.conf");
        fs::write(rootfs.join("etc/upstream-resolv.conf"), "# upstream\n").unwrap();
        fs::remove_file(&resolv).unwrap();
        std::os::unix::fs::symlink("upstream-resolv.conf", &resolv).unwrap();

        let profile = load_profile_from(&profile_yaml(dir, true, None, false));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        // Same command shape as prepare_only_restores_original — setup
        // (mv backup, cp temp, chmod) → teardown (rm temp, mv restore) — but
        // here the backed-up and restored entry is a symlink.
        assert!(
            fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&resolv).unwrap(), std::path::Path::new("upstream-resolv.conf"));
    }

    // A fresh systemd rootfs commonly ships `/etc/resolv.conf` as a *dangling*
    // symlink into `/run` (systemd-resolved not running yet) — exactly the
    // prepare+assemble scenario this PR targets. The prepare guard must detect
    // it with `symlink_metadata()` (which sees the link itself), not
    // `metadata()` (which follows the link and errors on the missing target):
    // detecting it as absent would skip the backup `mv` and then `cp` the
    // temporary file *through* the dangling link, failing setup. With the
    // guard correct, provisioning runs against a real temporary resolv.conf
    // and the assemble task's permanent symlink still lands.
    #[test]
    fn both_configured_dangling_symlink_original_survives() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let resolv = rootfs.join("etc/resolv.conf");
        // Dangling: the /run target does not exist in the seeded rootfs.
        fs::remove_file(&resolv).unwrap();
        std::os::unix::fs::symlink(LINK_TARGET, &resolv).unwrap();

        let profile = load_profile_from(&profile_yaml(dir, true, None, true));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile, executor.clone(), false).unwrap();

        // setup (mv backup, cp temp, chmod) → teardown (rm temp; the restore mv
        // is *skipped* because try_exists() follows the dangling backup link and
        // reports it absent, leaving the backup stranded — pre-existing
        // behavior) → assemble stage-and-rename (ln, mv). The permanent assemble
        // symlink is the final state.
        assert!(
            fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&resolv).unwrap(), std::path::Path::new(LINK_TARGET));
    }
}
