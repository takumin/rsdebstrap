//! Build artifacts the assemble phase writes next to the rootfs: a kernel, an initramfs,
//! assets such as boot firmware, and a squashfs image of the rootfs itself.
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
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use rustix::fs::{self as rfs, AtFlags, CWD, Mode, OFlags};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use strum::Display;
use tracing::info;

use crate::error::RsdebstrapError;
use crate::executor::{CommandExecutor, CommandSpec, PrivilegedProgram};
use crate::phase::PhaseItem;
use crate::privilege::PrivilegeMethod;
use crate::rootfs::{RelPath, RootfsOps};

/// Build artifacts to write into `dir` once the rootfs is final.
///
/// Each is written under its own name in `dir`, next to the bootstrap target, and replaces an
/// existing file of that name atomically. They are written in the order `kernel`,
/// `initramfs`, `assets`, `rootfs`, after every other assemble task.
#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    /// Copy the kernel image out of the rootfs.
    #[serde(default)]
    pub kernel: Option<BootFileOutput>,
    /// Copy the initramfs image out of the rootfs.
    #[serde(default)]
    pub initramfs: Option<BootFileOutput>,
    /// Files to place in `dir`, such as boot firmware, each downloaded, copied from the host,
    /// given inline or copied out of the rootfs. Written in list order.
    #[serde(default, deserialize_with = "crate::de::null_to_default")]
    #[schemars(with = "Option<Vec<AssetOutput>>")]
    pub assets: Vec<AssetOutput>,
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

/// Refuses a downloaded asset over this many bytes.
///
/// The download streams to a staging file, so this is not about memory: it keeps a server that
/// sends without end from filling the disk `dir` is on. Boot firmware is a few megabytes; this
/// leaves room for a kernel or a small image.
pub(crate) const MAX_ASSET_DOWNLOAD_SIZE: u64 = 1 << 30;

/// Mode an asset is written with, unless it is copied out of the rootfs.
const ASSET_MODE: u32 = 0o644;

/// Where an asset comes from: exactly one of `url`, `path`, `content` or `source`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetSource {
    /// An `https` URL, downloaded when the asset is written.
    Url(String),
    /// A file on the host.
    Path(Utf8PathBuf),
    /// The file's contents inline in the profile.
    Content(String),
    /// An absolute path inside the rootfs.
    Rootfs(String),
}

impl AssetSource {
    fn describe(&self) -> Cow<'_, str> {
        match self {
            Self::Url(url) => Cow::Borrowed(url),
            Self::Path(path) => Cow::Borrowed(path.as_str()),
            Self::Content(_) => Cow::Borrowed("inline content"),
            Self::Rootfs(source) => Cow::Owned(format!("{} in the rootfs", source)),
        }
    }
}

/// A file placed in `dir`, such as boot firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetOutput {
    pub file: String,
    pub source: AssetSource,
    /// Lowercase or uppercase hex SHA-256 of the file's bytes.
    pub sha256: Option<String>,
}

// Wire shape of an asset: one type drives both deserialization and schema generation, so the
// two cannot describe different shapes. Plain `//` so this note stays out of the schema.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("oneOf" = asset_source_one_of()))]
struct RawAssetOutput {
    /// Path of the file to write, relative to `dir`, such as `boot/start4.elf`. Missing
    /// directories are created. It may not lead into the bootstrap target.
    #[serde(deserialize_with = "crate::de::string")]
    file: String,
    /// `https` URL to download the file from. Requires `sha256`.
    #[serde(default, deserialize_with = "crate::de::opt_string")]
    url: Option<String>,
    /// Path to a file on the host. Relative paths are resolved against the profile's
    /// directory.
    #[serde(default, deserialize_with = "crate::de::opt_path")]
    #[schemars(with = "Option<crate::schema::Utf8PathSchema>")]
    path: Option<Utf8PathBuf>,
    /// The file's contents inline.
    #[serde(default, deserialize_with = "crate::de::opt_string")]
    content: Option<String>,
    /// Absolute path inside the rootfs to copy from, like `kernel.source`. Symlinks are
    /// followed, confined to the rootfs, and the copy keeps the source's permission bits.
    #[serde(default, deserialize_with = "crate::de::opt_string")]
    source: Option<String>,
    /// Expected SHA-256 of the file's bytes, as 64 hex digits. Checked before the file is
    /// put in place. Required with `url`, where the bytes are the server's to choose.
    #[serde(default, deserialize_with = "crate::de::opt_string")]
    sha256: Option<String>,
}

// The schema's copy of the rule `AssetOutput::deserialize` enforces. Each branch pins its
// field to a string, for the reason `schema::script_or_content` gives.
fn asset_source_one_of() -> serde_json::Value {
    serde_json::json!([
        {
            "required": ["url", "sha256"],
            "properties": { "url": { "type": "string" }, "sha256": { "type": "string" } }
        },
        { "required": ["path"], "properties": { "path": { "type": "string" } } },
        { "required": ["content"], "properties": { "content": { "type": "string" } } },
        { "required": ["source"], "properties": { "source": { "type": "string" } } },
    ])
}

impl<'de> Deserialize<'de> for AssetOutput {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawAssetOutput::deserialize(deserializer)?;
        let source = match (raw.url, raw.path, raw.content, raw.source) {
            (Some(url), None, None, None) => {
                if raw.sha256.is_none() {
                    return Err(serde::de::Error::custom(
                        "'url' requires 'sha256', so a changed download fails the build",
                    ));
                }
                AssetSource::Url(url)
            }
            (None, Some(path), None, None) => AssetSource::Path(path),
            (None, None, Some(content), None) => AssetSource::Content(content),
            (None, None, None, Some(source)) => AssetSource::Rootfs(source),
            (None, None, None, None) => {
                return Err(serde::de::Error::custom(
                    "one of 'url', 'path', 'content' or 'source' must be specified",
                ));
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "'url', 'path', 'content' and 'source' are mutually exclusive",
                ));
            }
        };
        Ok(Self {
            file: raw.file,
            source,
            sha256: raw.sha256,
        })
    }
}

impl JsonSchema for AssetOutput {
    fn schema_name() -> Cow<'static, str> {
        "AssetOutput".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        RawAssetOutput::json_schema(generator)
    }
}

impl AssetOutput {
    fn validate(&self) -> Result<(), RsdebstrapError> {
        validate_asset_file(&self.file)?;
        let invalid = |msg: String| {
            RsdebstrapError::Validation(format!("assemble output asset '{}': {}", self.file, msg))
        };
        if let Some(sha256) = &self.sha256
            && !(sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(invalid(format!("sha256 '{}' is not 64 hex digits", sha256)));
        }
        match &self.source {
            AssetSource::Url(url) => {
                let parsed = url::Url::parse(url)
                    .map_err(|e| invalid(format!("url '{}' is not a valid URL: {}", url, e)))?;
                if parsed.scheme() != "https" {
                    return Err(invalid(format!("url '{}' must use https", url)));
                }
                Ok(())
            }
            AssetSource::Path(path) => {
                crate::phase::validate_no_parent_dirs(path, "asset")?;
                crate::phase::validate_host_file_exists(path, "asset")
            }
            AssetSource::Content(_) => Ok(()),
            AssetSource::Rootfs(source) => source_path("asset", source).map(|_| ()),
        }
    }

    /// Resolves a relative `path` against `base_dir` (the profile's directory).
    fn resolve_paths(&mut self, base_dir: &Utf8Path) {
        if let AssetSource::Path(path) = &mut self.source
            && path.is_relative()
        {
            *path = base_dir.join(&*path);
        }
    }
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
        // Before the squashfs image, so a failed download or a checksum mismatch fails the
        // build before the slowest step rather than after it.
        items.extend(self.assets.iter().map(OutputItem::Asset));
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
            + self.assets.len()
            + usize::from(self.rootfs.is_some())
    }

    /// Resolves relative asset `path`s against `base_dir` (the profile's directory).
    pub fn resolve_paths(&mut self, base_dir: &Utf8Path) {
        for asset in &mut self.assets {
            asset.resolve_paths(base_dir);
        }
    }

    /// The file names the outputs are written under, in the order they are written.
    pub fn files(&self) -> Vec<&str> {
        self.items().iter().map(OutputItem::file).collect()
    }

    /// Refuses two outputs written under one name, which would leave only the last one, and
    /// an output written where another needs a directory (`boot` and `boot/start4.elf`).
    pub fn validate_distinct(&self) -> Result<(), RsdebstrapError> {
        let files = self.files();
        for (i, file) in files.iter().enumerate() {
            for earlier in &files[..i] {
                if earlier == file {
                    return Err(RsdebstrapError::Validation(format!(
                        "assemble output: more than one output is written to '{}'",
                        file
                    )));
                }
                let (outer, inner) = if file.len() < earlier.len() {
                    (file, earlier)
                } else {
                    (earlier, file)
                };
                if inner
                    .strip_prefix(outer)
                    .is_some_and(|rest| rest.starts_with('/'))
                {
                    return Err(RsdebstrapError::Validation(format!(
                        "assemble output: '{}' is written as a file, but '{}' needs it to be \
                        a directory",
                        outer, inner
                    )));
                }
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
    /// Downloads an asset given by `url`. A function pointer rather than a call to
    /// [`fetch_asset`] so tests can run without a network.
    pub fetch: AssetFetcher,
}

/// Downloads `url` into the sink it is handed.
pub(crate) type AssetFetcher = fn(&str, &mut dyn Write) -> Result<()>;

/// Downloads an asset over https, refusing a body over [`MAX_ASSET_DOWNLOAD_SIZE`].
pub(crate) fn fetch_asset(url: &str, sink: &mut dyn Write) -> Result<()> {
    crate::https::get_to_writer(url, MAX_ASSET_DOWNLOAD_SIZE, "asset", sink).map(|_| ())
}

/// One declared output, as the pipeline runs it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum OutputItem<'a> {
    Boot(BootFile, &'a BootFileOutput),
    Asset(&'a AssetOutput),
    Squashfs(&'a SquashfsOutput),
}

impl<'a> OutputItem<'a> {
    fn file(&self) -> &'a str {
        match self {
            Self::Boot(_, output) => &output.file,
            Self::Asset(asset) => &asset.file,
            Self::Squashfs(output) => &output.file,
        }
    }

    /// Writes this output into `ctx.dir`.
    pub(crate) fn write(&self, ctx: &OutputContext<'_>) -> Result<()> {
        match *self {
            Self::Boot(kind, output) => write_boot_file(kind, output, ctx),
            Self::Asset(asset) => write_asset(asset, ctx),
            Self::Squashfs(output) => write_squashfs(output, ctx),
        }
    }
}

impl PhaseItem for OutputItem<'_> {
    fn name(&self) -> Cow<'_, str> {
        match self {
            Self::Boot(kind, output) => Cow::Owned(format!("{}:{}", kind.label(), output.file)),
            Self::Asset(asset) => Cow::Owned(format!("asset:{}", asset.file)),
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
            Self::Asset(asset) => asset.validate(),
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

/// Refuses an asset `file` that is not a relative path down from `dir`.
///
/// Spelled canonically, so that [`OutputConfig::validate_distinct`] can compare names as
/// strings: `boot//start4.elf` and `boot/start4.elf/` name the same entry as
/// `boot/start4.elf`, and are refused rather than normalized.
fn validate_asset_file(file: &str) -> Result<(), RsdebstrapError> {
    let canonical = !file.is_empty()
        && !file.contains('\0')
        && file
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if !canonical {
        return Err(RsdebstrapError::Validation(format!(
            "assemble output asset: 'file' must be a relative path in `dir` without empty, \
            '.' or '..' components, got '{}'",
            file
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

fn write_asset(asset: &AssetOutput, ctx: &OutputContext<'_>) -> Result<()> {
    let destination = ctx.dir.join(&asset.file);

    if ctx.executor.dry_run() {
        info!("would write {} from {}", destination, asset.source.describe());
        return Ok(());
    }

    let components: Vec<&str> = asset.file.split('/').collect();
    let (name, parents) = components
        .split_last()
        .expect("a validated asset file has at least one component");
    let (parent, display_parent) = open_asset_dir(ctx.dir, parents)?;
    let (staged, file) = StagedOutput::create_at(parent, display_parent, name)?;
    let mut sink = HashingWriter::new(file);

    let mode = match &asset.source {
        AssetSource::Url(url) => {
            (ctx.fetch)(url, &mut sink)?;
            ASSET_MODE
        }
        AssetSource::Path(path) => {
            let bytes = crate::phase::read_host_file(path, "asset")?;
            sink.write_all(&bytes)
                .map_err(|e| RsdebstrapError::io(format!("failed to write {}", destination), e))?;
            ASSET_MODE
        }
        AssetSource::Content(content) => {
            sink.write_all(content.as_bytes())
                .map_err(|e| RsdebstrapError::io(format!("failed to write {}", destination), e))?;
            ASSET_MODE
        }
        AssetSource::Rootfs(source) => {
            let path = source_path("asset", source)?;
            let Some(exported) = ctx.ops.export_file(&path, &mut sink)? else {
                return Err(RsdebstrapError::Validation(format!(
                    "assemble output asset '{}': {} not found in the rootfs",
                    asset.file, source
                ))
                .into());
            };
            // The source's permission bits, as for the kernel and initramfs, but not its
            // set-id or sticky bits: the copy belongs to the user running the build, and a
            // setuid bit on it would mean nothing the rootfs intended.
            exported.mode.bits() & 0o777
        }
    };

    let (file, digest, size) = sink.finish();
    if let Some(expected) = &asset.sha256
        && !digest.eq_ignore_ascii_case(expected)
    {
        return Err(RsdebstrapError::Validation(format!(
            "assemble output asset '{}': sha256 mismatch: expected {}, got {}",
            asset.file, expected, digest
        ))
        .into());
    }
    rfs::fchmod(&file, Mode::from_raw_mode(mode))
        .map_err(std::io::Error::from)
        .and_then(|()| file.sync_all())
        .map_err(|e| RsdebstrapError::io(format!("failed to finish {}", destination), e))?;
    staged.publish()?;
    info!("wrote {} from {} ({} bytes)", destination, asset.source.describe(), size);
    Ok(())
}

/// Opens the directory `parents` names under `dir`, creating each one that is missing.
///
/// A component that is a symlink is refused rather than followed. Whether an asset lands inside
/// the bootstrap target is checked on its name when the profile is validated, and a link such
/// as `boot -> rootfs/boot` would otherwise put it into the image anyway.
fn open_asset_dir(
    dir: &Utf8Path,
    parents: &[&str],
) -> Result<(OwnedFd, Utf8PathBuf), RsdebstrapError> {
    let mut fd = rfs::openat(
        CWD,
        dir.as_str(),
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| RsdebstrapError::io(format!("failed to open {}", dir), e.into()))?;
    let mut display = dir.to_owned();
    for name in parents {
        display.push(name);
        match rfs::mkdirat(&fd, *name, Mode::from_raw_mode(0o755)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(e) => {
                return Err(RsdebstrapError::io(format!("failed to create {}", display), e.into()));
            }
        }
        fd = rfs::openat(
            &fd,
            *name,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| match e {
            rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => RsdebstrapError::Validation(
                format!("{} is not a directory (a symlink is not followed)", display),
            ),
            other => RsdebstrapError::io(format!("failed to open {}", display), other.into()),
        })?;
    }
    Ok((fd, display))
}

/// Passes writes through to a file while hashing and counting them, so a download is checked
/// against its `sha256` without being held in memory or read back.
struct HashingWriter {
    file: File,
    hasher: Sha256,
    size: u64,
}

impl HashingWriter {
    fn new(file: File) -> Self {
        Self {
            file,
            hasher: Sha256::new(),
            size: 0,
        }
    }

    /// Returns the file, the hex SHA-256 of what was written, and its size.
    fn finish(self) -> (File, String, u64) {
        let digest = self
            .hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        (self.file, digest, self.size)
    }
}

impl Write for HashingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.file.write(buf)?;
        self.hasher.update(&buf[..written]);
        self.size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
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
        Self::create_at(dir_fd, dir.to_owned(), file)
    }

    /// [`create`](Self::create) in a directory that is already open.
    fn create_at(
        dir_fd: OwnedFd,
        display_dir: Utf8PathBuf,
        file: &str,
    ) -> Result<(Self, File), RsdebstrapError> {
        let staging = format!(".{}.rsdebstrap-{}", file, uuid::Uuid::new_v4().simple());
        let fd = rfs::openat(
            dir_fd.as_fd(),
            staging.as_str(),
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| {
            RsdebstrapError::io(format!("failed to create {}/{}", display_dir, staging), e.into())
        })?;
        Ok((
            Self {
                dir: dir_fd,
                display_dir,
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
            fetch: fake_fetch,
        })
    }

    // Serves a fixed body for one URL and fails for any other, as a missing file would.
    fn fake_fetch(url: &str, sink: &mut dyn Write) -> Result<()> {
        match url {
            "https://example.com/start4.elf" => {
                sink.write_all(b"firmware")?;
                Ok(())
            }
            _ => anyhow::bail!("404 for {}", url),
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    fn asset(file: &str, source: AssetSource, sha256: Option<String>) -> AssetOutput {
        AssetOutput {
            file: file.to_string(),
            source,
            sha256,
        }
    }

    fn content(file: &str, body: &str) -> AssetOutput {
        asset(file, AssetSource::Content(body.to_string()), None)
    }

    fn write_assets(
        assets: &[AssetOutput],
        dir: &Utf8Path,
        rootfs: &Utf8Path,
        executor: &FakeMksquashfs,
    ) -> Result<()> {
        for a in assets {
            write(OutputItem::Asset(a), dir, rootfs, executor)?;
        }
        Ok(())
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
            assets: Vec::new(),
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

    #[test]
    fn deserialize_assets_from_each_source() {
        let yaml = concat!(
            "assets:\n",
            "- file: boot/start4.elf\n",
            "  url: https://example.com/start4.elf\n",
            "  sha256: 0000000000000000000000000000000000000000000000000000000000000000\n",
            "- file: boot/config.txt\n  path: ./config.txt\n",
            "- file: boot/cmdline.txt\n  content: \"console=tty1\\n\"\n",
            "- file: boot/bcm2711-rpi-4-b.dtb\n  source: /usr/lib/firmware/bcm2711-rpi-4-b.dtb\n",
        );
        let config: OutputConfig = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(config.len(), 4);
        let sources: Vec<_> = config.assets.iter().map(|a| a.source.clone()).collect();
        assert_eq!(
            sources,
            [
                AssetSource::Url("https://example.com/start4.elf".to_string()),
                AssetSource::Path(Utf8PathBuf::from("./config.txt")),
                AssetSource::Content("console=tty1\n".to_string()),
                AssetSource::Rootfs("/usr/lib/firmware/bcm2711-rpi-4-b.dtb".to_string()),
            ]
        );
    }

    #[test]
    fn deserialize_rejects_an_asset_with_no_source_or_two() {
        for yaml in [
            "assets:\n- file: a\n",
            "assets:\n- file: a\n  content: x\n  source: /a\n",
        ] {
            assert!(yaml_serde::from_str::<OutputConfig>(yaml).is_err(), "{yaml}");
        }
    }

    // A downloaded file is the server's to choose, so an unpinned URL is not accepted at all
    // rather than warned about.
    #[test]
    fn deserialize_rejects_a_url_without_sha256() {
        let yaml = "assets:\n- file: a\n  url: https://example.com/a\n";
        let err = yaml_serde::from_str::<OutputConfig>(yaml).unwrap_err();
        assert!(err.to_string().contains("sha256"), "{err}");
    }

    #[test]
    fn deserialize_null_assets_is_empty() {
        let config: OutputConfig = yaml_serde::from_str("assets: null\n").unwrap();
        assert!(config.assets.is_empty());
    }

    #[test]
    fn items_write_assets_before_the_squashfs_image() {
        let yaml = concat!(
            "rootfs:\n  file: rootfs.squashfs\n",
            "assets:\n- file: boot/a\n  content: a\n- file: boot/b\n  content: b\n",
            "kernel:\n  file: vmlinuz\n",
        );
        let config: OutputConfig = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(config.files(), vec!["vmlinuz", "boot/a", "boot/b", "rootfs.squashfs"]);
    }

    #[test]
    fn validate_refuses_an_asset_file_that_is_not_a_canonical_relative_path() {
        for file in [
            "",
            "/boot/start4.elf",
            "boot//start4.elf",
            "boot/start4.elf/",
            "./start4.elf",
            "boot/../start4.elf",
            "..",
        ] {
            let a = content(file, "x");
            let err = OutputItem::Asset(&a).validate().unwrap_err();
            assert!(err.to_string().contains("relative path"), "{file}: {err}");
        }
        OutputItem::Asset(&content("boot/overlays/a.dtbo", "x"))
            .validate()
            .unwrap();
    }

    #[test]
    fn validate_refuses_a_plain_http_url_and_a_malformed_sha256() {
        let http =
            asset("a", AssetSource::Url("http://example.com/a".to_string()), Some("0".repeat(64)));
        let err = OutputItem::Asset(&http).validate().unwrap_err();
        assert!(err.to_string().contains("https"), "{err}");

        let short = asset("a", AssetSource::Content("x".to_string()), Some("abc".to_string()));
        let err = OutputItem::Asset(&short).validate().unwrap_err();
        assert!(err.to_string().contains("64 hex digits"), "{err}");
    }

    #[test]
    fn validate_refuses_a_relative_rootfs_source() {
        let a = asset("a", AssetSource::Rootfs("usr/lib/a".to_string()), None);
        assert!(OutputItem::Asset(&a).validate().is_err());
    }

    #[test]
    fn validate_distinct_refuses_a_file_another_output_needs_as_a_directory() {
        let config = OutputConfig {
            kernel: Some(boot("boot", None)),
            assets: vec![content("boot/start4.elf", "x")],
            ..OutputConfig::default()
        };
        let err = config.validate_distinct().unwrap_err();
        assert!(err.to_string().contains("needs it to be a directory"), "{err}");

        // A shared prefix that is not a whole component is not a conflict.
        let config = OutputConfig {
            kernel: Some(boot("boot", None)),
            assets: vec![content("bootfs/start4.elf", "x")],
            ..OutputConfig::default()
        };
        config.validate_distinct().unwrap();
    }

    #[test]
    fn validate_distinct_refuses_two_assets_with_one_file() {
        let config = OutputConfig {
            assets: vec![content("boot/a", "x"), content("boot/a", "y")],
            ..OutputConfig::default()
        };
        assert!(config.validate_distinct().is_err());
    }

    #[test]
    fn assets_are_written_into_created_directories() {
        let (_tmp, dir, rootfs) = build_dir();
        let host = dir.join("config.txt");
        std::fs::write(&host, b"arm_64bit=1\n").unwrap();
        let assets = [
            asset(
                "boot/start4.elf",
                AssetSource::Url("https://example.com/start4.elf".to_string()),
                Some(sha256_hex(b"firmware")),
            ),
            asset("boot/config.txt", AssetSource::Path(host), None),
            content("boot/overlays/README", "overlays"),
        ];

        write_assets(&assets, &dir, &rootfs, &FakeMksquashfs::new()).unwrap();

        assert_eq!(std::fs::read(dir.join("boot/start4.elf")).unwrap(), b"firmware");
        assert_eq!(std::fs::read(dir.join("boot/config.txt")).unwrap(), b"arm_64bit=1\n");
        assert_eq!(std::fs::read(dir.join("boot/overlays/README")).unwrap(), b"overlays");
        let mode = std::fs::metadata(dir.join("boot/start4.elf"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o644);
        assert_eq!(entries(&dir.join("boot")), vec!["config.txt", "overlays", "start4.elf"]);
    }

    #[test]
    fn an_asset_is_copied_out_of_the_rootfs_with_its_permission_bits() {
        let (_tmp, dir, rootfs) = build_dir();
        let dtb = rootfs.join("boot/board.dtb");
        std::fs::write(&dtb, b"dtb").unwrap();
        std::fs::set_permissions(&dtb, std::fs::Permissions::from_mode(0o4750)).unwrap();
        let a = asset("boot/board.dtb", AssetSource::Rootfs("/boot/board.dtb".to_string()), None);

        write_assets(&[a], &dir, &rootfs, &FakeMksquashfs::new()).unwrap();

        let copy = dir.join("boot/board.dtb");
        assert_eq!(std::fs::read(&copy).unwrap(), b"dtb");
        let mode = std::fs::metadata(&copy).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o750, "permission bits are kept, the setuid bit is not");
    }

    #[test]
    fn a_missing_rootfs_source_is_an_error_that_leaves_nothing() {
        let (_tmp, dir, rootfs) = build_dir();
        let a = asset("board.dtb", AssetSource::Rootfs("/boot/board.dtb".to_string()), None);

        let err = write_assets(&[a], &dir, &rootfs, &FakeMksquashfs::new()).unwrap_err();

        assert!(err.to_string().contains("not found in the rootfs"), "{err}");
        assert_eq!(entries(&dir), vec!["rootfs"]);
    }

    #[test]
    fn a_sha256_mismatch_leaves_the_existing_file() {
        let (_tmp, dir, rootfs) = build_dir();
        std::fs::write(dir.join("start4.elf"), b"old firmware").unwrap();
        let a = asset(
            "start4.elf",
            AssetSource::Url("https://example.com/start4.elf".to_string()),
            Some(sha256_hex(b"other firmware")),
        );

        let err = write_assets(&[a], &dir, &rootfs, &FakeMksquashfs::new()).unwrap_err();

        assert!(err.to_string().contains("sha256 mismatch"), "{err}");
        assert_eq!(std::fs::read(dir.join("start4.elf")).unwrap(), b"old firmware");
        assert_eq!(entries(&dir), vec!["rootfs", "start4.elf"], "no staging entry is left");
    }

    #[test]
    fn a_failed_download_leaves_no_file() {
        let (_tmp, dir, rootfs) = build_dir();
        let a = asset(
            "start4.elf",
            AssetSource::Url("https://example.com/missing".to_string()),
            Some("0".repeat(64)),
        );

        let err = write_assets(&[a], &dir, &rootfs, &FakeMksquashfs::new()).unwrap_err();

        assert!(err.to_string().contains("404"), "{err}");
        assert_eq!(entries(&dir), vec!["rootfs"]);
    }

    // `boot` is a symlink into the bootstrap target here. Following it would put the asset in
    // the image, past the check that refuses `rootfs/...` by name.
    #[test]
    fn a_symlinked_directory_on_the_way_is_refused() {
        let (_tmp, dir, rootfs) = build_dir();
        std::os::unix::fs::symlink("rootfs/boot", dir.join("boot")).unwrap();

        let err = write_assets(
            &[content("boot/cmdline.txt", "x")],
            &dir,
            &rootfs,
            &FakeMksquashfs::new(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("not a directory"), "{err}");
        assert_eq!(entries(&rootfs.join("boot")), Vec::<String>::new());
    }

    #[test]
    fn dry_run_writes_no_asset_and_creates_no_directory() {
        let (_tmp, dir, rootfs) = build_dir();
        let executor = FakeMksquashfs {
            dry_run: true,
            ..FakeMksquashfs::new()
        };

        write_assets(&[content("boot/cmdline.txt", "x")], &dir, &rootfs, &executor).unwrap();

        assert_eq!(entries(&dir), vec!["rootfs"]);
    }

    // Needs the network, so it is `#[ignore]`d; run it with `cargo test -- --ignored` to check
    // the streamed download against a real server.
    #[test]
    #[ignore]
    fn fetch_asset_streams_a_real_file() {
        let mut body = Vec::new();
        fetch_asset("https://download.docker.com/linux/debian/gpg", &mut body).unwrap();
        assert!(body.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    }
}
