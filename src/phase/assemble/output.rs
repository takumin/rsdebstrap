//! Build artifacts the assemble phase writes next to the rootfs: a kernel, an initramfs,
//! and a squashfs image of the rootfs itself.
//!
//! These are not `AssembleItem`s. An assemble item writes the
//! rootfs's final state and cannot run a program; an output reads that final state and
//! writes *outside* the rootfs, and packing it into a squashfs image means running
//! `mksquashfs`. So outputs are declarations the pipeline acts on once every assemble item
//! has run, the way prepare tasks are declarations the pipeline's guards act on: the program
//! is a fixed [`PrivilegedProgram`], not something a profile names, and nothing that runs
//! comes from inside the rootfs.

use std::borrow::Cow;
use std::fs::File;
use std::os::fd::OwnedFd;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use rustix::fs::{self as rfs, AtFlags, CWD, Mode, OFlags};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strum::Display;
use tracing::info;

use crate::error::RsdebstrapError;
use crate::executor::{CommandExecutor, CommandSpec, PrivilegedProgram};
use crate::phase::PhaseItem;
use crate::privilege::PrivilegeMethod;
use crate::rootfs::{RelPath, RootfsOps};

/// Build artifacts to write into `dir` once the rootfs is final.
///
/// Each is written under its own name directly in `dir`, next to the bootstrap target, and
/// replaces an existing file of that name atomically. They are written in the order
/// `kernel`, `initramfs`, `rootfs`, after every other assemble task.
#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    /// Copy the kernel image out of the rootfs.
    #[serde(default)]
    pub kernel: Option<BootFileOutput>,
    /// Copy the initramfs image out of the rootfs.
    #[serde(default)]
    pub initramfs: Option<BootFileOutput>,
    /// Pack the rootfs into a squashfs image with `mksquashfs`.
    #[serde(default)]
    pub rootfs: Option<SquashfsOutput>,
}

/// A file copied out of the rootfs, such as the kernel or the initramfs.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BootFileOutput {
    /// Name of the file to write in `dir` (a plain file name, not a path).
    #[serde(deserialize_with = "crate::de::string")]
    pub file: String,
    /// Absolute path inside the rootfs to copy from. Symlinks are followed, confined to the
    /// rootfs. When omitted, the kernel is looked up at `/vmlinuz` then `/boot/vmlinuz`, and
    /// the initramfs at `/initrd.img` then `/boot/initrd.img` -- the links Debian's kernel
    /// packages maintain to the newest installed version.
    #[serde(
        default,
        deserialize_with = "crate::de::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub source: Option<String>,
}

/// The rootfs packed into a squashfs image.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SquashfsOutput {
    /// Name of the image to write in `dir` (a plain file name, not a path).
    #[serde(deserialize_with = "crate::de::string")]
    pub file: String,
    /// Compression algorithm passed to `mksquashfs -comp`. When omitted, `mksquashfs`
    /// uses its own default (gzip).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression: Option<SquashfsCompression>,
}

/// Compression algorithms `mksquashfs` accepts for `-comp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum SquashfsCompression {
    Gzip,
    Lzo,
    Lz4,
    Xz,
    Zstd,
}

/// Which boot file a [`BootFileOutput`] is, for its default sources and its messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootFile {
    Kernel,
    Initramfs,
}

impl BootFile {
    fn label(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Initramfs => "initramfs",
        }
    }

    fn default_sources(self) -> &'static [&'static str] {
        match self {
            Self::Kernel => &["/vmlinuz", "/boot/vmlinuz"],
            Self::Initramfs => &["/initrd.img", "/boot/initrd.img"],
        }
    }
}

impl OutputConfig {
    /// Returns the declared outputs in the order they are written.
    pub(crate) fn items(&self) -> Vec<OutputItem<'_>> {
        let mut items = Vec::new();
        if let Some(kernel) = &self.kernel {
            items.push(OutputItem::Boot(BootFile::Kernel, kernel));
        }
        if let Some(initramfs) = &self.initramfs {
            items.push(OutputItem::Boot(BootFile::Initramfs, initramfs));
        }
        if let Some(rootfs) = &self.rootfs {
            items.push(OutputItem::Squashfs(rootfs));
        }
        items
    }

    /// Returns true if no outputs are declared.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of declared outputs.
    pub fn len(&self) -> usize {
        usize::from(self.kernel.is_some())
            + usize::from(self.initramfs.is_some())
            + usize::from(self.rootfs.is_some())
    }

    /// The file names the outputs are written under, in the order they are written.
    pub fn files(&self) -> Vec<&str> {
        self.items().iter().map(OutputItem::file).collect()
    }

    /// Refuses two outputs written under one name, which would leave only the last one.
    pub fn validate_distinct(&self) -> Result<(), RsdebstrapError> {
        let files = self.files();
        for (i, file) in files.iter().enumerate() {
            if files[..i].contains(file) {
                return Err(RsdebstrapError::Validation(format!(
                    "assemble output: more than one output is written to '{}'",
                    file
                )));
            }
        }
        Ok(())
    }
}

/// What the pipeline hands an output to write with.
pub(crate) struct OutputContext<'a> {
    pub rootfs: &'a Utf8Path,
    pub dir: &'a Utf8Path,
    pub ops: &'a dyn RootfsOps,
    pub executor: &'a dyn CommandExecutor,
    /// The run's `defaults.privilege`. It escalates `mksquashfs` for the same reason it
    /// escalates the rootfs helper: a rootfs built under `sudo` has files only root can read.
    pub privilege: Option<PrivilegeMethod>,
}

/// One declared output, as the pipeline runs it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum OutputItem<'a> {
    Boot(BootFile, &'a BootFileOutput),
    Squashfs(&'a SquashfsOutput),
}

impl<'a> OutputItem<'a> {
    fn file(&self) -> &'a str {
        match self {
            Self::Boot(_, output) => &output.file,
            Self::Squashfs(output) => &output.file,
        }
    }

    /// Writes this output into `ctx.dir`.
    pub(crate) fn write(&self, ctx: &OutputContext<'_>) -> Result<()> {
        match *self {
            Self::Boot(kind, output) => write_boot_file(kind, output, ctx),
            Self::Squashfs(output) => write_squashfs(output, ctx),
        }
    }
}

impl PhaseItem for OutputItem<'_> {
    fn name(&self) -> Cow<'_, str> {
        match self {
            Self::Boot(kind, output) => Cow::Owned(format!("{}:{}", kind.label(), output.file)),
            Self::Squashfs(output) => Cow::Owned(format!("rootfs:{}", output.file)),
        }
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        match self {
            Self::Boot(kind, output) => {
                validate_file_name(kind.label(), &output.file)?;
                if let Some(source) = &output.source {
                    source_path(kind.label(), source)?;
                }
                Ok(())
            }
            Self::Squashfs(output) => validate_file_name("rootfs", &output.file),
        }
    }
}

/// Refuses an output name that is not a single entry directly in `dir`.
///
/// A name with a separator or a `..` would put the output somewhere other than next to the
/// rootfs, and one inside the rootfs would end up in the image it is packed from.
fn validate_file_name(label: &str, file: &str) -> Result<(), RsdebstrapError> {
    if file.is_empty() || file == "." || file == ".." || file.contains('/') || file.contains('\0') {
        return Err(RsdebstrapError::Validation(format!(
            "assemble output {}: 'file' must be a plain file name in `dir`, got '{}'",
            label, file
        )));
    }
    Ok(())
}

fn source_path(label: &str, source: &str) -> Result<RelPath, RsdebstrapError> {
    if !source.starts_with('/') {
        return Err(RsdebstrapError::Validation(format!(
            "assemble output {}: 'source' must be an absolute path inside the rootfs, got '{}'",
            label, source
        )));
    }
    RelPath::parse(source).map_err(|e| {
        RsdebstrapError::Validation(format!("assemble output {}: invalid 'source': {}", label, e))
    })
}

fn write_boot_file(kind: BootFile, output: &BootFileOutput, ctx: &OutputContext<'_>) -> Result<()> {
    let sources: Vec<&str> = match &output.source {
        Some(source) => vec![source.as_str()],
        None => kind.default_sources().to_vec(),
    };
    let destination = ctx.dir.join(&output.file);

    if ctx.executor.dry_run() {
        info!(
            "would copy the {} from {} in {} to {}",
            kind.label(),
            sources.join(" or "),
            ctx.rootfs,
            destination
        );
        return Ok(());
    }

    let (staged, mut file) = StagedOutput::create(ctx.dir, &output.file)?;
    for source in &sources {
        let path = source_path(kind.label(), source)?;
        let Some(exported) = ctx.ops.export_file(&path, &mut file)? else {
            continue;
        };
        // The source's own mode, not a fixed one: Debian installs an initramfs readable by
        // root only, because it can carry key material, and the copy should not widen that.
        rfs::fchmod(&file, Mode::from_raw_mode(exported.mode.bits()))
            .map_err(std::io::Error::from)
            .and_then(|()| file.sync_all())
            .map_err(|e| RsdebstrapError::io(format!("failed to finish {}", destination), e))?;
        staged.publish()?;
        info!(
            "copied the {} from {}{} to {} ({} bytes)",
            kind.label(),
            ctx.rootfs,
            source,
            destination,
            exported.size
        );
        return Ok(());
    }

    Err(RsdebstrapError::Validation(format!(
        "no {} found in the rootfs at {} (is a kernel package installed?)",
        kind.label(),
        sources.join(" or ")
    ))
    .into())
}

fn write_squashfs(output: &SquashfsOutput, ctx: &OutputContext<'_>) -> Result<()> {
    let destination = ctx.dir.join(&output.file);

    // Staged under a fresh name and renamed into place, so a failed or interrupted
    // `mksquashfs` never leaves a partial image under the name a consumer reads. Created
    // here, as the invoking user, rather than by `mksquashfs`: `-noappend` truncates it in
    // place, so the image stays owned by the user who ran the build even when `mksquashfs`
    // runs as root, and keeps the owner-only mode it was created with -- it holds every file
    // of the rootfs, `/etc/shadow` included.
    let staged = if ctx.executor.dry_run() {
        None
    } else {
        Some(StagedOutput::create(ctx.dir, &output.file)?.0)
    };
    let target = staged
        .as_ref()
        .map_or_else(|| destination.clone(), StagedOutput::path);

    let mut args = vec![
        ctx.rootfs.to_string(),
        target.to_string(),
        "-noappend".to_string(),
        // Anything still mounted under the rootfs is not part of the image: the pipeline
        // unmounted what it mounted before assembly, so a mount here is one something else
        // left behind, and packing it would put the build host's `/proc` in the image.
        "-one-file-system".to_string(),
    ];
    if let Some(compression) = output.compression {
        args.push("-comp".to_string());
        args.push(compression.to_string());
    }

    let spec = CommandSpec::privileged(PrivilegedProgram::Mksquashfs, args, ctx.privilege);
    ctx.executor
        .execute_checked(&spec)
        .with_context(|| format!("failed to pack {} into {}", ctx.rootfs, destination))?;

    if let Some(staged) = staged {
        staged.publish()?;
        info!("packed {} into {}", ctx.rootfs, destination);
    }
    Ok(())
}

/// An output being written under a staging name in `dir`, removed unless it is published.
///
/// The staging entry is a sibling of the output so that publishing it is a same-directory
/// `renameat`, which replaces an existing output atomically. `dir` is the invoking user's
/// directory and this runs as that user, so none of the rootfs's descriptor anchoring is
/// needed here -- what it protects against is a consumer of `dir` reading a half-written
/// file, and a failed build leaving one behind.
struct StagedOutput {
    dir: OwnedFd,
    display_dir: Utf8PathBuf,
    staging: String,
    file: String,
    published: bool,
}

impl StagedOutput {
    fn create(dir: &Utf8Path, file: &str) -> Result<(Self, File), RsdebstrapError> {
        let dir_fd = rfs::openat(
            CWD,
            dir.as_str(),
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| RsdebstrapError::io(format!("failed to open {}", dir), e.into()))?;
        let staging = format!(".{}.rsdebstrap-{}", file, uuid::Uuid::new_v4().simple());
        let fd = rfs::openat(
            &dir_fd,
            staging.as_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| {
            RsdebstrapError::io(format!("failed to create {}/{}", dir, staging), e.into())
        })?;
        Ok((
            Self {
                dir: dir_fd,
                display_dir: dir.to_owned(),
                staging,
                file: file.to_string(),
                published: false,
            },
            File::from(fd),
        ))
    }

    fn path(&self) -> Utf8PathBuf {
        self.display_dir.join(&self.staging)
    }

    fn publish(mut self) -> Result<(), RsdebstrapError> {
        rfs::renameat(&self.dir, self.staging.as_str(), &self.dir, self.file.as_str()).map_err(
            |e| {
                RsdebstrapError::io(
                    format!("failed to install {}", self.display_dir.join(&self.file)),
                    e.into(),
                )
            },
        )?;
        self.published = true;
        Ok(())
    }
}

impl Drop for StagedOutput {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        match rfs::unlinkat(&self.dir, self.staging.as_str(), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(e) => tracing::error!(path = %self.path(), "failed to remove staged output: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    use super::*;
    use crate::executor::ExecutionResult;
    use crate::rootfs::LocalRootfsOps;

    // Stands in for `mksquashfs`: records the spec and, unless told to fail, writes an
    // image to the path it was handed, the way the real program fills the staged file.
    struct FakeMksquashfs {
        specs: Mutex<Vec<CommandSpec>>,
        fail: bool,
        dry_run: bool,
    }

    impl FakeMksquashfs {
        fn new() -> Self {
            Self {
                specs: Mutex::new(Vec::new()),
                fail: false,
                dry_run: false,
            }
        }
    }

    impl CommandExecutor for FakeMksquashfs {
        fn execute(&self, spec: &CommandSpec) -> Result<ExecutionResult> {
            self.specs.lock().unwrap().push(spec.clone());
            if self.dry_run {
                return Ok(ExecutionResult { status: None });
            }
            std::fs::write(&spec.args()[1], b"hsqs image").unwrap();
            let code = if self.fail { 1 << 8 } else { 0 };
            Ok(ExecutionResult {
                status: Some(std::os::unix::process::ExitStatusExt::from_raw(code)),
            })
        }

        fn dry_run(&self) -> bool {
            self.dry_run
        }
    }

    // `dir` with a bootstrapped-looking rootfs inside it, as the pipeline sees them.
    fn build_dir() -> (tempfile::TempDir, Utf8PathBuf, Utf8PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).unwrap();
        let rootfs = dir.join("rootfs");
        std::fs::create_dir_all(rootfs.join("boot")).unwrap();
        (tmp, dir, rootfs)
    }

    fn entries(dir: &Utf8Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn write(
        item: OutputItem<'_>,
        dir: &Utf8Path,
        rootfs: &Utf8Path,
        executor: &FakeMksquashfs,
    ) -> Result<()> {
        let ops = LocalRootfsOps::open(rootfs).unwrap();
        item.write(&OutputContext {
            rootfs,
            dir,
            ops: &ops,
            executor,
            privilege: None,
        })
    }

    fn boot(file: &str, source: Option<&str>) -> BootFileOutput {
        BootFileOutput {
            file: file.to_string(),
            source: source.map(str::to_string),
        }
    }

    #[test]
    fn deserialize_all_outputs() {
        let yaml = concat!(
            "kernel:\n  file: vmlinuz\n",
            "initramfs:\n  file: initrd.img\n  source: /boot/initrd.img-6.12.0-amd64\n",
            "rootfs:\n  file: rootfs.squashfs\n  compression: zstd\n",
        );
        let config: OutputConfig = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(config.len(), 3);
        assert_eq!(config.files(), vec!["vmlinuz", "initrd.img", "rootfs.squashfs"]);
        assert_eq!(config.rootfs.unwrap().compression, Some(SquashfsCompression::Zstd));
    }

    #[test]
    fn deserialize_rejects_an_unknown_compression() {
        let yaml = "rootfs:\n  file: rootfs.squashfs\n  compression: brotli\n";
        assert!(yaml_serde::from_str::<OutputConfig>(yaml).is_err());
    }

    #[test]
    fn deserialize_rejects_a_privilege_key() {
        // Escalation for `mksquashfs` is the run's `defaults.privilege`, as it is for
        // every rootfs access after bootstrap; a per-output key could not be honored.
        let yaml = "rootfs:\n  file: rootfs.squashfs\n  privilege: true\n";
        assert!(yaml_serde::from_str::<OutputConfig>(yaml).is_err());
    }

    #[test]
    fn validate_refuses_a_file_that_is_not_a_plain_name() {
        for file in [
            "",
            ".",
            "..",
            "out/vmlinuz",
            "/tmp/vmlinuz",
            "rootfs/boot/vmlinuz",
        ] {
            let output = boot(file, None);
            let err = OutputItem::Boot(BootFile::Kernel, &output)
                .validate()
                .unwrap_err();
            assert!(err.to_string().contains("plain file name"), "{file}: {err}");
        }
    }

    #[test]
    fn validate_refuses_a_relative_or_escaping_source() {
        for source in ["boot/vmlinuz", "/boot/../../vmlinuz"] {
            let output = boot("vmlinuz", Some(source));
            assert!(
                OutputItem::Boot(BootFile::Kernel, &output)
                    .validate()
                    .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn validate_distinct_refuses_a_shared_file_name() {
        let config = OutputConfig {
            kernel: Some(boot("boot.img", None)),
            initramfs: Some(boot("boot.img", None)),
            rootfs: None,
        };
        let err = config.validate_distinct().unwrap_err();
        assert!(err.to_string().contains("boot.img"), "{err}");
    }

    #[test]
    fn kernel_is_copied_through_the_default_link() {
        let (_tmp, dir, rootfs) = build_dir();
        std::fs::write(rootfs.join("boot/vmlinuz-6.12.0-amd64"), b"kernel").unwrap();
        std::os::unix::fs::symlink("boot/vmlinuz-6.12.0-amd64", rootfs.join("vmlinuz")).unwrap();
        let output = boot("vmlinuz", None);

        write(
            OutputItem::Boot(BootFile::Kernel, &output),
            &dir,
            &rootfs,
            &FakeMksquashfs::new(),
        )
        .unwrap();

        assert_eq!(std::fs::read(dir.join("vmlinuz")).unwrap(), b"kernel");
        assert_eq!(entries(&dir), vec!["rootfs", "vmlinuz"], "no staging entry is left");
    }

    // Some installations keep the links in `/boot` (`link_in_boot = yes`), so the second
    // default is tried when the first resolves to nothing.
    #[test]
    fn initramfs_falls_back_to_the_link_in_boot() {
        let (_tmp, dir, rootfs) = build_dir();
        let image = rootfs.join("boot/initrd.img-6.12.0-amd64");
        std::fs::write(&image, b"initramfs").unwrap();
        std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink("initrd.img-6.12.0-amd64", rootfs.join("boot/initrd.img"))
            .unwrap();
        let output = boot("initrd.img", None);

        write(
            OutputItem::Boot(BootFile::Initramfs, &output),
            &dir,
            &rootfs,
            &FakeMksquashfs::new(),
        )
        .unwrap();

        let copy = dir.join("initrd.img");
        assert_eq!(std::fs::read(&copy).unwrap(), b"initramfs");
        let mode = std::fs::metadata(&copy).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "the copy keeps the source's mode");
    }

    #[test]
    fn an_explicit_source_is_the_only_one_tried() {
        let (_tmp, dir, rootfs) = build_dir();
        std::fs::write(rootfs.join("boot/vmlinuz-6.12.0-amd64"), b"kernel").unwrap();
        std::os::unix::fs::symlink("boot/vmlinuz-6.12.0-amd64", rootfs.join("vmlinuz")).unwrap();
        let output = boot("vmlinuz", Some("/boot/vmlinuz-6.13.0-amd64"));

        let err = write(
            OutputItem::Boot(BootFile::Kernel, &output),
            &dir,
            &rootfs,
            &FakeMksquashfs::new(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("/boot/vmlinuz-6.13.0-amd64"), "{err}");
        assert_eq!(entries(&dir), vec!["rootfs"], "nothing is left behind");
    }

    #[test]
    fn a_missing_kernel_is_an_error_that_names_where_it_looked() {
        let (_tmp, dir, rootfs) = build_dir();
        let output = boot("vmlinuz", None);

        let err = write(
            OutputItem::Boot(BootFile::Kernel, &output),
            &dir,
            &rootfs,
            &FakeMksquashfs::new(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("/vmlinuz or /boot/vmlinuz"), "{err}");
        assert_eq!(entries(&dir), vec!["rootfs"], "nothing is left behind");
    }

    #[test]
    fn an_existing_output_is_replaced() {
        let (_tmp, dir, rootfs) = build_dir();
        std::fs::write(rootfs.join("vmlinuz"), b"new kernel").unwrap();
        std::fs::write(dir.join("vmlinuz"), b"old kernel").unwrap();
        let output = boot("vmlinuz", None);

        write(
            OutputItem::Boot(BootFile::Kernel, &output),
            &dir,
            &rootfs,
            &FakeMksquashfs::new(),
        )
        .unwrap();

        assert_eq!(std::fs::read(dir.join("vmlinuz")).unwrap(), b"new kernel");
    }

    #[test]
    fn squashfs_is_packed_by_mksquashfs_and_published() {
        let (_tmp, dir, rootfs) = build_dir();
        let output = SquashfsOutput {
            file: "rootfs.squashfs".to_string(),
            compression: Some(SquashfsCompression::Zstd),
        };
        let executor = FakeMksquashfs::new();

        write(OutputItem::Squashfs(&output), &dir, &rootfs, &executor).unwrap();

        let specs = executor.specs.lock().unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].command(), "mksquashfs");
        let args = specs[0].args();
        assert_eq!(args[0], rootfs.as_str());
        // Written under a staging name next to the output, not at the output itself.
        assert_ne!(args[1], dir.join("rootfs.squashfs").as_str());
        assert!(args[1].starts_with(dir.join(".rootfs.squashfs.rsdebstrap-").as_str()));
        assert_eq!(&args[2..], ["-noappend", "-one-file-system", "-comp", "zstd"]);

        let image = dir.join("rootfs.squashfs");
        assert_eq!(std::fs::read(&image).unwrap(), b"hsqs image");
        let mode = std::fs::metadata(&image).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "the image holds every file of the rootfs");
        assert_eq!(entries(&dir), vec!["rootfs", "rootfs.squashfs"]);
    }

    #[test]
    fn a_failed_mksquashfs_leaves_no_image() {
        let (_tmp, dir, rootfs) = build_dir();
        let output = SquashfsOutput {
            file: "rootfs.squashfs".to_string(),
            compression: None,
        };
        let executor = FakeMksquashfs {
            fail: true,
            ..FakeMksquashfs::new()
        };

        assert!(write(OutputItem::Squashfs(&output), &dir, &rootfs, &executor).is_err());
        assert_eq!(entries(&dir), vec!["rootfs"], "the partial image is removed");
    }

    #[test]
    fn dry_run_writes_nothing() {
        let (_tmp, dir, rootfs) = build_dir();
        let executor = FakeMksquashfs {
            dry_run: true,
            ..FakeMksquashfs::new()
        };
        let kernel = boot("vmlinuz", None);
        let image = SquashfsOutput {
            file: "rootfs.squashfs".to_string(),
            compression: None,
        };

        write(OutputItem::Boot(BootFile::Kernel, &kernel), &dir, &rootfs, &executor).unwrap();
        write(OutputItem::Squashfs(&image), &dir, &rootfs, &executor).unwrap();

        // The command is still handed over, so the dry run reports it.
        let specs = executor.specs.lock().unwrap();
        assert_eq!(specs[0].args()[1], dir.join("rootfs.squashfs").as_str());
        assert_eq!(entries(&dir), vec!["rootfs"]);
    }
}
