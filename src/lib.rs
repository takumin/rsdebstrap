pub mod bootstrap;
pub mod checksum;
pub mod cli;
pub mod condition;
pub mod config;
pub(crate) mod de;
pub mod envs;
pub mod error;
pub mod executor;
pub(crate) mod https;
pub mod isolation;
pub mod phase;
pub mod pipeline;
pub mod privilege;
pub mod rootfs;
pub mod schema;
pub mod vars;

pub use error::RsdebstrapError;

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use camino::Utf8Path;
use serde::Serialize;
use tracing::{info, warn};
use tracing_subscriber::{FmtSubscriber, filter::LevelFilter};

use crate::executor::CommandExecutor;
use crate::isolation::apt_sources::{self, fetch_https};
use crate::isolation::mount::RootfsMounts;
use crate::isolation::resolv_conf::RootfsResolvConf;
use crate::privilege::PrivilegeMethod;

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
    env: &[envs::ResolvedEnv],
) -> Result<()> {
    let backend = profile.bootstrap.as_backend();
    let program = backend.program();
    let command_name = program.program_name();

    let args = backend
        .build_args(&profile.dir)
        .with_context(|| format!("failed to build arguments for {}", command_name))?;

    let privilege = profile
        .bootstrap
        .resolve_privilege(profile.defaults.privilege.as_ref())?;
    let spec = executor::CommandSpec::privileged(
        executor::PrivilegedProgram::Bootstrap(program),
        args,
        privilege,
    )
    .with_envs(env.iter().map(envs::ResolvedEnv::pair));
    executor
        .execute_checked(&spec)
        .with_context(|| format!("failed to execute {}", command_name))?;

    Ok(())
}

/// Whether the bootstrap or a provision task that will run escalates with `doas` — the
/// commands `envs` reaches.
fn uses_doas(validated: &config::ValidatedProfile<'_>) -> Result<bool> {
    let profile = validated.profile();
    let bootstrap = profile
        .bootstrap
        .resolve_privilege(profile.defaults.privilege.as_ref())?;
    Ok(std::iter::once(bootstrap)
        .chain(validated.pipeline()?.provision_privileges())
        .any(|privilege| privilege == Some(PrivilegeMethod::Doas)))
}

// Prints the names among its arguments that are unset, and fails if there are any. Only
// whether a variable is set is checked: `printenv`'s value goes to /dev/null, never into
// the output, which the executor logs.
const DOAS_ENV_CHECK: &str = r#"missing=
for name do
    printenv "$name" > /dev/null || missing="$missing $name"
done
[ -z "$missing" ] && exit 0
echo "not passed by doas:$missing" >&2
exit 1"#;

/// Checks, before anything is built, that `doas` passes `env` to what it runs.
///
/// `sudo` is asked to keep the variables with `--preserve-env`, and refuses the command if
/// its policy does not allow that. `doas` has no such option: it keeps a variable only if
/// `doas.conf` says so (`setenv { NAME }` or `keepenv`), and otherwise drops it without a
/// word, so a proxy or a token would go missing from a build that then fails, or succeeds,
/// for reasons nobody can see. This runs one `doas` command with the variables and has it
/// report the ones that did not arrive.
///
/// The command is the host's `/bin/sh` under `chroot /`, because `chroot` is the
/// [`PrivilegedProgram`](executor::PrivilegedProgram) that runs a program; `/` makes it a
/// no-op, and the shell only tests variables.
fn check_doas_env(executor: &Arc<dyn CommandExecutor>, env: &[envs::ResolvedEnv]) -> Result<()> {
    let names: Vec<&str> = env.iter().map(envs::ResolvedEnv::name).collect();
    let args = ["/", "/bin/sh", "-c", DOAS_ENV_CHECK, "sh"]
        .into_iter()
        .chain(names.iter().copied())
        .map(str::to_string)
        .collect();
    let spec = executor::CommandSpec::privileged(
        executor::PrivilegedProgram::Chroot,
        args,
        Some(PrivilegeMethod::Doas),
    )
    .with_envs(env.iter().map(envs::ResolvedEnv::pair));
    let result = executor
        .execute(&spec)
        .context("failed to check the environment doas passes")?;
    if result.success() {
        return Ok(());
    }
    Err(RsdebstrapError::Validation(format!(
        "doas did not pass every `envs` variable (the missing ones are logged above, unless \
        doas itself refused the command). doas keeps only what doas.conf allows: add \
        `setenv {{ {} }}` to the rule this user runs as root with, for example \
        `permit setenv {{ {} }} <user> as root`",
        names.join(" "),
        names.join(" "),
    ))
    .into())
}

/// Executes the pipeline phase (prepare, provision, assemble).
fn run_pipeline_phase(
    validated: &config::ValidatedProfile<'_>,
    executor: Arc<dyn CommandExecutor>,
) -> Result<()> {
    run_pipeline_phase_with(validated, executor, None)
}

/// [`run_pipeline_phase`] with the rootfs operations supplied rather than opened.
///
/// `ops` is `None` in production, where the privilege setting decides which
/// implementation to open. Tests pass one in to drive rootfs failure paths.
fn run_pipeline_phase_with(
    validated: &config::ValidatedProfile<'_>,
    executor: Arc<dyn CommandExecutor>,
    ops: Option<Arc<dyn rootfs::RootfsOps>>,
) -> Result<()> {
    let profile = validated.profile();
    // The executor owns whether this is a dry run; every other layer derives it from there.
    let dry_run = executor.dry_run();
    let pipeline = validated.pipeline()?;

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

    // Resolved once, here, and nowhere with privilege. Every consumer below anchors to this
    // path -- the rootfs ops, the mounts, the program walk direct execution does -- and each
    // of those opens it a component at a time without following anything, so a symlink the
    // user legitimately has on the way has to be resolved before them or it is refused.
    let rootfs = rootfs::resolve_prefix(&rootfs);

    let mount_entries = profile
        .prepare
        .mount
        .as_ref()
        .map(|m| m.resolved_mounts())
        .unwrap_or_default();
    let privilege = profile.defaults.privilege.as_ref().map(|d| d.method);
    let mut mounts = RootfsMounts::new(&rootfs, mount_entries, executor.clone(), privilege);
    let mounted = mounts
        .mount()
        .context("failed to mount filesystems in rootfs")?;

    // Escalate once for the whole build: `rootfs::open` spawns a single helper
    // when privilege is configured, and every rootfs mutation from here on is a
    // typed request to it rather than its own `sudo` invocation.
    let ops = match ops {
        Some(ops) => ops,
        None => rootfs::open(&rootfs, privilege, dry_run)?,
    };

    // What `prepare.apt` writes stays, so it has no guard to unwind. A setup failure from
    // here on is cleaned up by the guards' `Drop`, in reverse order.
    let apt_configured = apt_sources::configure(
        mounted,
        profile.prepare.apt.as_ref(),
        ops.as_ref(),
        dry_run,
        fetch_https,
    )
    .context("failed to configure apt repositories in rootfs")?;

    let resolv_conf_config = profile.prepare.resolv_conf.as_ref().map(|rc| rc.config());
    let mut resolv_conf = RootfsResolvConf::new(
        &rootfs,
        resolv_conf_config,
        Utf8Path::new("/etc/resolv.conf"),
        ops.clone(),
        dry_run,
    );
    let prepared = resolv_conf
        .setup(apt_configured)
        .context("failed to set up resolv.conf in rootfs")?;

    // The ordering below is carried by `Provisioned`/`Restored`/`Unmounted`: each stage
    // takes a token only the previous one can produce. Why restore and unmount both have to
    // land before assembly is in `docs/ARCHITECTURE.md` (Phases & the pipeline).
    let restored = match pipeline.run_prepare_and_provision(prepared, &rootfs, &executor, &ops) {
        Ok(provisioned) => mounts
            .still_mounted()
            .and_then(|mounted| resolv_conf.restore(provisioned, mounted))
            .context(
                "failed to restore resolv.conf after provisioning; \
                any assemble tasks were skipped",
            ),
        Err(run_err) => {
            // `Drop` would restore too, but only after the unmount below; the
            // restores belong inside the mounted window.
            if let Err(restore_err) = resolv_conf.teardown() {
                tracing::error!("resolv.conf restore also failed: {:#}", restore_err);
            }
            Err(run_err)
        }
    };

    // Unmounting is attempted whichever way the stages above went; only the
    // token it yields is gated on their success.
    match restored {
        Ok(token) => match mounts.unmount_before_assembly(token) {
            Ok(unmounted) => pipeline.run_assemble(unmounted, &rootfs, &executor, &ops),
            Err(e) => Err(e).context(
                "failed to unmount filesystems after provisioning; \
                any assemble tasks were skipped",
            ),
        },
        Err(pipeline_err) => {
            // Dropped before the unmount, not at the end of this function. The guard's
            // `Drop` is the last retry of a restore that has not landed, and it has to run
            // inside the mounted window: with a `prepare.mount` over the directory it
            // writes into, a retry afterwards puts the original on the directory underneath
            // and leaves the temporary on the mounted filesystem, with nothing reporting a
            // problem. A guard whose restore already succeeded is torn down, so this costs
            // that path nothing.
            drop(resolv_conf);
            if let Err(u) = mounts.unmount() {
                tracing::error!(
                    "unmount also failed after pipeline error: {:#}. \
                    Drop guard will attempt cleanup.",
                    u
                );
            }
            Err(pipeline_err)
        }
    }
}

/// Runs the `apply` command against `common`, using `executor` for every program it runs.
///
/// Takes [`cli::CommonArgs`] rather than the whole [`cli::ApplyArgs`] so that `--dry-run` is
/// not in scope here. `main` is the one place that turns the flag into an executor, and from
/// there the executor is the single answer to whether this is a dry run — a caller cannot
/// hand in one that disagrees with a flag, because there is no flag to disagree with.
pub fn run_apply(common: &cli::CommonArgs, executor: Arc<dyn CommandExecutor>) -> Result<()> {
    let dry_run = executor.dry_run();
    if dry_run {
        warn!("DRY-RUN MODE: No changes will be made");
    }

    let profile = load_profile(common)?;
    let validated = profile.validate().context("profile validation failed")?;

    if !dry_run && !profile.dir.exists() {
        fs::create_dir_all(&profile.dir)
            .with_context(|| format!("failed to create directory: {}", profile.dir))?;
    }

    let env = envs::resolve(&profile.envs)?;
    if !env.is_empty() {
        let shown: Vec<String> = env.iter().map(ToString::to_string).collect();
        info!("environment for bootstrap and provision: {}", shown.join(" "));
    }

    if !env.is_empty() && uses_doas(&validated)? {
        check_doas_env(&executor, &env)?;
    }

    run_bootstrap_phase(&profile, &executor, &env)?;
    run_pipeline_phase(&validated, executor)?;

    Ok(())
}

fn load_profile(common: &cli::CommonArgs) -> Result<config::Profile> {
    let overrides = vars::VarOverrides::from_process_env(common.vars.iter().cloned())?;
    config::load_profile_with_vars(common.file.as_path(), &overrides)
        .with_context(|| format!("failed to load profile from {}", common.file))
}

pub fn run_validate(opts: &cli::ValidateArgs) -> Result<()> {
    let profile = load_profile(&opts.common)?;
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
        // Really runs what it is given, so it must not claim otherwise: these tests
        // assert the resulting filesystem state.
        fn dry_run(&self) -> bool {
            false
        }

        fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
            self.commands
                .lock()
                .unwrap()
                .push((spec.command().to_string(), spec.args().to_vec()));

            let status = std::process::Command::new(spec.command())
                .args(spec.args())
                .envs(spec.env().iter().cloned())
                .status()?;
            Ok(ExecutionResult {
                status: Some(status),
            })
        }
    }

    const LINK_ASSEMBLE: &str =
        "assemble:\n  resolv_conf:\n    link: ../run/systemd/resolve/stub-resolv.conf\n";
    const GENERATE_ASSEMBLE: &str = "assemble:\n  resolv_conf:\n    name_servers: [198.51.100.1]\n";

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
        // For shell provision tasks (DirectProvider): a real /tmp for the staged script,
        // and a real /bin/sh so the recording executor can actually run it. A *copy* of
        // the host shell rather than a symlink to it — `DirectContext` refuses to exec a
        // program whose path leaves the rootfs, which is the shape a symlink here has.
        fs::create_dir_all(rootfs.join("tmp")).unwrap();
        fs::create_dir_all(rootfs.join("bin")).unwrap();
        fs::copy("/bin/sh", rootfs.join("bin/sh")).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(rootfs.join("bin/sh"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        rootfs
    }

    const LINK_TARGET: &str = "../run/systemd/resolve/stub-resolv.conf";

    // Wraps real ops and fails one chosen operation. Rootfs mutations do not run as
    // commands, so a failure has to be injected at this layer rather than by making an
    // argv exit non-zero.
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
        fn export_file(
            &self,
            path: &rootfs::RelPath,
            sink: &mut dyn std::io::Write,
        ) -> std::result::Result<Option<rootfs::ExportedFile>, RsdebstrapError> {
            self.inner.export_file(path, sink)
        }

        fn write_file(
            &self,
            path: &rootfs::RelPath,
            content: &[u8],
            mode: rootfs::FileMode,
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
            target: &[u8],
        ) -> std::result::Result<(), RsdebstrapError> {
            if self.fail == Failure::Symlink {
                return Err(refused("symlink"));
            }
            self.inner.write_symlink(path, target)
        }

        // Through this mock's own writers, so a restore is one of the writes the
        // `Failure` cases count.
        fn put_back(
            &self,
            path: &rootfs::RelPath,
            entry: &rootfs::TakenEntry,
        ) -> std::result::Result<(), RsdebstrapError> {
            match entry {
                rootfs::TakenEntry::File { content, mode, .. } => {
                    self.write_file(path, content, *mode)
                }
                rootfs::TakenEntry::Symlink { target, .. } => self.write_symlink(path, target),
            }
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

        fn create_dir(
            &self,
            path: &rootfs::RelPath,
            mode: rootfs::FileMode,
        ) -> std::result::Result<bool, RsdebstrapError> {
            self.inner.create_dir(path, mode)
        }

        fn remove_dir(&self, path: &rootfs::RelPath) -> std::result::Result<bool, RsdebstrapError> {
            self.inner.remove_dir(path)
        }

        fn clear_dir(
            &self,
            path: &rootfs::RelPath,
            keep: &[String],
        ) -> std::result::Result<u64, RsdebstrapError> {
            self.inner.clear_dir(path, keep)
        }
    }

    // Timeline shared by the executor and the ops below, so the mount lifecycle
    // (commands) and the assemble writes (syscalls) can be ordered against each
    // other. Neither layer touches the real system: mount/umount are recorded
    // rather than run.
    type Timeline = Arc<Mutex<Vec<String>>>;

    struct TimelineExecutor {
        timeline: Timeline,
    }

    impl CommandExecutor for TimelineExecutor {
        // The point of this test is the order real mounts and writes happen in, so the
        // run has to be a live one even though nothing is actually mounted.
        fn dry_run(&self) -> bool {
            false
        }

        fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
            self.timeline
                .lock()
                .unwrap()
                .push(spec.command().to_string());
            Ok(ExecutionResult { status: None })
        }
    }

    struct TimelineOps {
        inner: rootfs::LocalRootfsOps,
        timeline: Timeline,
        // Fails the first `put_back` when set, so the guard's first restore attempt fails
        // and its `Drop` is what finally lands the original.
        fail_first_put_back: bool,
        put_backs: std::sync::atomic::AtomicUsize,
    }

    impl TimelineOps {
        fn new(rootfs: &Utf8Path, timeline: Timeline) -> Self {
            Self {
                inner: rootfs::LocalRootfsOps::open(rootfs).unwrap(),
                timeline,
                fail_first_put_back: false,
                put_backs: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn failing_first_restore(rootfs: &Utf8Path, timeline: Timeline) -> Self {
            Self {
                fail_first_put_back: true,
                ..Self::new(rootfs, timeline)
            }
        }
    }

    impl rootfs::RootfsOps for TimelineOps {
        fn export_file(
            &self,
            path: &rootfs::RelPath,
            sink: &mut dyn std::io::Write,
        ) -> std::result::Result<Option<rootfs::ExportedFile>, RsdebstrapError> {
            self.timeline
                .lock()
                .unwrap()
                .push("export_file".to_string());
            self.inner.export_file(path, sink)
        }

        fn write_file(
            &self,
            path: &rootfs::RelPath,
            content: &[u8],
            mode: rootfs::FileMode,
        ) -> std::result::Result<(), RsdebstrapError> {
            self.timeline.lock().unwrap().push("write_file".to_string());
            self.inner.write_file(path, content, mode)
        }

        fn write_symlink(
            &self,
            path: &rootfs::RelPath,
            target: &[u8],
        ) -> std::result::Result<(), RsdebstrapError> {
            self.timeline
                .lock()
                .unwrap()
                .push("write_symlink".to_string());
            self.inner.write_symlink(path, target)
        }

        fn put_back(
            &self,
            path: &rootfs::RelPath,
            entry: &rootfs::TakenEntry,
        ) -> std::result::Result<(), RsdebstrapError> {
            let nth = self
                .put_backs
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail_first_put_back && nth == 0 {
                self.timeline
                    .lock()
                    .unwrap()
                    .push("put_back(failed)".to_string());
                return Err(refused("put_back"));
            }
            self.timeline.lock().unwrap().push("put_back".to_string());
            self.inner.put_back(path, entry)
        }

        fn remove(&self, path: &rootfs::RelPath) -> std::result::Result<(), RsdebstrapError> {
            self.inner.remove(path)
        }

        fn take(
            &self,
            path: &rootfs::RelPath,
        ) -> std::result::Result<Option<rootfs::TakenEntry>, RsdebstrapError> {
            self.inner.take(path)
        }

        fn create_dir(
            &self,
            path: &rootfs::RelPath,
            mode: rootfs::FileMode,
        ) -> std::result::Result<bool, RsdebstrapError> {
            self.inner.create_dir(path, mode)
        }

        fn remove_dir(&self, path: &rootfs::RelPath) -> std::result::Result<bool, RsdebstrapError> {
            self.inner.remove_dir(path)
        }

        fn clear_dir(
            &self,
            path: &rootfs::RelPath,
            keep: &[String],
        ) -> std::result::Result<u64, RsdebstrapError> {
            self.inner.clear_dir(path, keep)
        }
    }

    // Assemble writes the rootfs's final state — what the image is built from —
    // so it has to see the rootfs the way the image will, with nothing bound
    // over it. The mounts therefore close before assemble opens, not after.
    #[test]
    fn assemble_runs_after_the_mounts_are_released() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let mut yaml = profile_yaml(dir, false, None, true);
        // Mounts require a configured privilege method; nothing escalates here,
        // because both the executor and the ops are the recorders above.
        yaml.push_str("defaults:\n  privilege:\n    method: sudo\n");
        yaml.push_str("prepare:\n  mount:\n    mounts:\n      - source: /dev\n");
        yaml.push_str("        target: /dev\n        options: [bind]\n");
        let profile = load_profile_from(&yaml);

        let timeline: Timeline = Arc::new(Mutex::new(Vec::new()));
        let executor = Arc::new(TimelineExecutor {
            timeline: timeline.clone(),
        });
        let ops = Arc::new(TimelineOps::new(&rootfs, timeline.clone()));

        run_pipeline_phase_with(&profile.validate().unwrap(), executor, Some(ops)).unwrap();

        assert_eq!(
            *timeline.lock().unwrap(),
            ["mount", "umount", "write_symlink"],
            "assemble must run after the mounts are released"
        );
    }

    // The guard's `Drop` is the last retry of a restore that has not landed, and it has to
    // run while the mounts are still up: a `prepare.mount` over the directory the restore
    // writes into means the temporary went onto the mounted filesystem, so a retry after
    // the unmount puts the original on the directory underneath and leaves the temporary
    // where the rootfs will actually read it. Nothing errors, which is why the order is
    // pinned here rather than left to the end of the function.
    #[test]
    fn the_restore_retry_lands_before_the_unmount() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let mut yaml = profile_yaml(dir, false, None, false);
        yaml.push_str("defaults:\n  privilege:\n    method: sudo\n");
        yaml.push_str("prepare:\n  resolv_conf:\n    name_servers: [192.0.2.1]\n");
        yaml.push_str("  mount:\n    mounts:\n      - source: /dev\n");
        yaml.push_str("        target: /dev\n        options: [bind]\n");
        let profile = load_profile_from(&yaml);

        let timeline: Timeline = Arc::new(Mutex::new(Vec::new()));
        let executor = Arc::new(TimelineExecutor {
            timeline: timeline.clone(),
        });
        let ops = Arc::new(TimelineOps::failing_first_restore(&rootfs, timeline.clone()));

        let err = run_pipeline_phase_with(&profile.validate().unwrap(), executor, Some(ops))
            .expect_err("the failed restore must fail the run");
        assert!(
            format!("{err:#}").contains("failed to restore resolv.conf"),
            "unexpected error: {err:#}"
        );

        let recorded = timeline.lock().unwrap().clone();
        let retry = recorded
            .iter()
            .position(|e| e == "put_back")
            .expect("the guard's Drop retries the restore");
        let umount = recorded
            .iter()
            .position(|e| e == "umount")
            .expect("the mounts are released on the error path too");
        assert!(retry < umount, "the retry must land inside the mounted window: {recorded:?}");
    }

    #[test]
    fn both_configured_assemble_output_survives() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, None, true));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

        let resolv = rootfs.join("etc/resolv.conf");
        assert!(
            fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&resolv).unwrap(), std::path::Path::new(LINK_TARGET));
    }

    // Runs the check script itself, as `doas` would leave it: some variables passed, some not.
    #[test]
    fn doas_env_check_names_the_unset_variables_without_their_values() {
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", DOAS_ENV_CHECK, "sh", "SET", "EMPTY", "GONE"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("SET", "s3cret")
            .env("EMPTY", "")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(stdout, "");
        assert_eq!(stderr, "not passed by doas: GONE\n");

        let passed = std::process::Command::new("/bin/sh")
            .args(["-c", DOAS_ENV_CHECK, "sh", "SET"])
            .env("SET", "x")
            .output()
            .unwrap();
        assert!(passed.status.success(), "{passed:?}");
        assert!(passed.stdout.is_empty() && passed.stderr.is_empty(), "{passed:?}");
    }

    // Answers every command with a fixed exit status and keeps the spec, so the check can be
    // driven without a real `doas`.
    struct FixedStatusExecutor {
        code: i32,
        specs: Mutex<Vec<CommandSpec>>,
    }

    impl CommandExecutor for FixedStatusExecutor {
        fn dry_run(&self) -> bool {
            false
        }

        fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
            use std::os::unix::process::ExitStatusExt;

            self.specs.lock().unwrap().push(spec.clone());
            Ok(ExecutionResult {
                status: Some(std::process::ExitStatus::from_raw(self.code << 8)),
            })
        }
    }

    fn resolved_env(yaml: &str) -> Vec<envs::ResolvedEnv> {
        let profile = load_profile_from(&format!(
            "dir: /tmp/unused\n{yaml}bootstrap:\n  type: mmdebstrap\n  suite: trixie\n  \
            target: rootfs\n"
        ));
        envs::resolve(&profile.envs).unwrap()
    }

    #[test]
    fn doas_env_check_runs_the_script_under_doas_with_the_variables() {
        let env = resolved_env("envs:\n  A: one\n  B:\n    value: two\n    sensitive: true\n");
        let executor = Arc::new(FixedStatusExecutor {
            code: 0,
            specs: Mutex::new(Vec::new()),
        });
        check_doas_env(&(executor.clone() as Arc<dyn CommandExecutor>), &env).unwrap();

        let specs = executor.specs.lock().unwrap();
        let [spec] = specs.as_slice() else {
            panic!("expected one command, got {}", specs.len());
        };
        assert_eq!(spec.command(), "chroot");
        assert_eq!(spec.privilege(), Some(PrivilegeMethod::Doas));
        assert_eq!(&spec.args()[..5], ["/", "/bin/sh", "-c", DOAS_ENV_CHECK, "sh"]);
        assert_eq!(&spec.args()[5..], ["A", "B"]);
        assert_eq!(
            spec.env(),
            [
                ("A".to_owned(), "one".to_owned()),
                ("B".to_owned(), "two".to_owned())
            ]
        );
    }

    #[test]
    fn doas_env_check_failure_names_the_doas_conf_rule() {
        let env = resolved_env("envs:\n  HTTP_PROXY: http://proxy:3128\n  TOKEN: x\n");
        let executor: Arc<dyn CommandExecutor> = Arc::new(FixedStatusExecutor {
            code: 1,
            specs: Mutex::new(Vec::new()),
        });
        let err = check_doas_env(&executor, &env).unwrap_err().to_string();
        assert!(err.contains("permit setenv { HTTP_PROXY TOKEN } <user> as root"), "{err}");
    }

    // The check is for `doas` wherever `envs` reaches: the bootstrap, or a provision task
    // that overrides a `sudo` default. A task `when:` leaves out does not count.
    #[test]
    fn uses_doas_looks_at_the_bootstrap_and_the_provision_tasks_that_run() {
        let profile = |defaults: &str, bootstrap: &str, task: &str| {
            load_profile_from(&format!(
                "dir: /tmp/unused\nvars:\n  on: 'no'\ndefaults:\n  privilege:\n    \
                method: {defaults}\nbootstrap:\n  type: mmdebstrap\n  suite: trixie\n  \
                target: rootfs\n  privilege: {bootstrap}\nprovision:\n  - type: shell\n    \
                content: 'true'\n{task}"
            ))
        };
        for (defaults, bootstrap, task, expected) in [
            ("sudo", "true", "", false),
            ("doas", "true", "", true),
            ("doas", "false", "    privilege: false\n", false),
            ("sudo", "true", "    privilege: { method: doas }\n", true),
            (
                "sudo",
                "true",
                "    privilege: { method: doas }\n    when: vars.on == 'yes'\n",
                false,
            ),
        ] {
            let profile = profile(defaults, bootstrap, task);
            let got = uses_doas(&profile.validate().unwrap()).unwrap();
            assert_eq!(got, expected, "defaults {defaults}, bootstrap {bootstrap}, task {task:?}");
        }
    }

    // A pass-through name that is unset is left out, so the shell sees it unset rather
    // than empty; `${VAR-unset}` tells the two apart.
    #[test]
    fn provision_tasks_receive_the_profile_envs() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        seed_rootfs(dir);
        let out = dir.join("env.out");
        let yaml = format!(
            "dir: {dir}\n\
            envs:\n  RSDEBSTRAP_TEST_SET: from profile\n  RSDEBSTRAP_TEST_UNSET_VAR:\n\
            bootstrap:\n  type: mmdebstrap\n  suite: trixie\n  target: rootfs\n\
            provision:\n  - type: shell\n    isolation: false\n    content: \
            'printf \"%s|%s\" \"$RSDEBSTRAP_TEST_SET\" \
            \"${{RSDEBSTRAP_TEST_UNSET_VAR-unset}}\" > {out}'\n"
        );
        let profile = load_profile_from(&yaml);
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

        assert_eq!(fs::read_to_string(&out).unwrap(), "from profile|unset");
    }

    #[test]
    fn prepare_only_restores_original() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, None, false));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

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

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

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

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

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
            run_pipeline_phase_with(&profile.validate().unwrap(), executor.clone(), Some(ops))
                .unwrap_err();

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
            run_pipeline_phase_with(&profile.validate().unwrap(), executor.clone(), Some(ops))
                .unwrap_err();

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

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

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

        let err = run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap_err();

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
            run_pipeline_phase_with(&profile.validate().unwrap(), executor.clone(), Some(ops))
                .unwrap_err();

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

    #[test]
    fn a_failed_restore_leaves_no_orphan_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        let profile = load_profile_from(&profile_yaml(dir, true, None, true));
        let executor = RecordingExecutor::new();
        let ops = FailingOps::boxed(&rootfs, Failure::SecondWrite);

        let err =
            run_pipeline_phase_with(&profile.validate().unwrap(), executor.clone(), Some(ops))
                .unwrap_err();

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

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

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

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

        assert!(executor.command_names().is_empty(), "no command should have run");
        let resolv = rootfs.join("etc/resolv.conf");
        assert!(fs::symlink_metadata(&resolv).unwrap().file_type().is_file());
        assert!(
            fs::read_to_string(&resolv)
                .unwrap()
                .contains("nameserver 198.51.100.1")
        );
    }

    const OUTPUT_ASSEMBLE: &str = "assemble:\n  resolv_conf:\n    name_servers: [198.51.100.1]\n  \
        output:\n    kernel:\n      file: vmlinuz\n    initramfs:\n      file: initrd.img\n";

    #[test]
    fn assemble_copies_the_kernel_and_initramfs_out_of_the_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        let rootfs = seed_rootfs(dir);
        fs::create_dir(rootfs.join("boot")).unwrap();
        fs::write(rootfs.join("boot/vmlinuz-6.12.0-amd64"), "kernel").unwrap();
        fs::write(rootfs.join("boot/initrd.img-6.12.0-amd64"), "initramfs").unwrap();
        std::os::unix::fs::symlink("boot/vmlinuz-6.12.0-amd64", rootfs.join("vmlinuz")).unwrap();
        std::os::unix::fs::symlink("boot/initrd.img-6.12.0-amd64", rootfs.join("initrd.img"))
            .unwrap();
        let profile =
            load_profile_from(&profile_yaml_with_assemble(dir, false, None, Some(OUTPUT_ASSEMBLE)));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

        assert!(executor.command_names().is_empty(), "copying out runs no program");
        assert_eq!(fs::read_to_string(dir.join("vmlinuz")).unwrap(), "kernel");
        assert_eq!(fs::read_to_string(dir.join("initrd.img")).unwrap(), "initramfs");
    }

    // Runs the real `mksquashfs`, which a development machine may not have; validation
    // refuses the profile without it, so there is nothing to test there.
    #[test]
    fn assemble_packs_the_final_rootfs_into_a_squashfs_image() {
        if which::which("mksquashfs").is_err() || which::which("unsquashfs").is_err() {
            eprintln!("skipping: mksquashfs/unsquashfs not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8Path::from_path(tmp.path()).unwrap();
        seed_rootfs(dir);
        let assemble = "assemble:\n  resolv_conf:\n    name_servers: [198.51.100.1]\n  \
            output:\n    rootfs:\n      file: rootfs.squashfs\n";
        let profile =
            load_profile_from(&profile_yaml_with_assemble(dir, false, None, Some(assemble)));
        let executor = RecordingExecutor::new();

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

        assert_eq!(executor.command_names(), vec!["mksquashfs"]);
        // Read back out of the image: the resolv.conf the assemble task wrote is in it, so
        // the image was packed from the rootfs in its final state.
        let listed = std::process::Command::new("unsquashfs")
            .args([
                "-cat",
                dir.join("rootfs.squashfs").as_str(),
                "etc/resolv.conf",
            ])
            .output()
            .unwrap();
        assert!(listed.status.success(), "{listed:?}");
        assert!(String::from_utf8_lossy(&listed.stdout).contains("nameserver 198.51.100.1"));
    }

    // Debian's default `/etc/resolv.conf` is a *symlink*, not a regular file, yet every
    // other pipeline-level test seeds a regular file. The prepare guard must detach the
    // symlink and restore it faithfully as a symlink, not flatten it into a regular file.
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

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

        // Same shape as prepare_only_restores_original, but the detached and restored
        // entry is a symlink.
        assert!(
            fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&resolv).unwrap(), std::path::Path::new("upstream-resolv.conf"));
    }

    // A fresh systemd rootfs commonly ships `/etc/resolv.conf` as a *dangling* symlink into
    // `/run` (systemd-resolved not running yet). Nothing in the prepare guard may stat
    // through it: reading it as absent would skip the detach and then write the temporary
    // file *through* the dangling link.
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

        run_pipeline_phase(&profile.validate().unwrap(), executor.clone()).unwrap();

        assert!(
            fs::symlink_metadata(&resolv)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&resolv).unwrap(), std::path::Path::new(LINK_TARGET));
        // The restore runs even though the original is a dangling link: it is held as a
        // symlink value, never stat'd through. Nothing may be stranded in /etc.
        let etc: Vec<String> = fs::read_dir(rootfs.join("etc"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(etc, ["resolv.conf"], "unexpected leftovers in /etc: {etc:?}");
    }
}
