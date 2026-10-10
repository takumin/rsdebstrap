//! mitamae plugins: where a profile says one comes from, how it is read or fetched, and how
//! it is staged into the rootfs for `mitamae local --plugins`.
//!
//! Every source is reduced to the same thing before anything reaches the rootfs: the
//! plugin's `mrblib` tree, held in memory. That is all mitamae reads from a plugin --
//! resource plugins are loaded from `mrblib/**/*.rb` and recipe plugins are found under
//! `mrblib/{,m}itamae/plugin/recipe/` -- so a checkout's `.git`, specs and the rest never
//! leave the host. All of `mrblib` is taken rather than only its `.rb` files, because a
//! recipe plugin's templates and files sit next to its recipes.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use rustix::fd::{AsFd, OwnedFd};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::Deserialize;
use tracing::{debug, info};

use crate::checksum::Checksum;
use crate::error::RsdebstrapError;
use crate::rootfs::{FileMode, RelPath, RootfsOps};

/// A mitamae plugin and where it comes from.
///
/// Clones share what was fetched: `defaults.mitamae.plugins` is copied into every mitamae
/// task, and a plugin named there is downloaded once per run, not once per task.
#[derive(Clone)]
pub struct MitamaePlugin {
    name: Option<String>,
    source: MitamaePluginSource,
    fetched: Arc<OnceLock<Arc<PluginTree>>>,
}

/// Where a mitamae plugin's files come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MitamaePluginSource {
    /// A plugin directory on the host.
    Path(Utf8PathBuf),
    /// A git repository, at a commit.
    Git { url: String, commit: String },
    /// A tar archive (optionally gzip-compressed) downloaded over https, with its checksum.
    Archive { url: String, checksum: Checksum },
}

impl PartialEq for MitamaePlugin {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.source == other.source
    }
}

impl Eq for MitamaePlugin {}

// Hand-written so a fetched tree -- every byte of every file -- stays out of debug output.
impl std::fmt::Debug for MitamaePlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MitamaePlugin")
            .field("name", &self.name)
            .field("source", &self.source)
            .field("fetched", &self.fetched.get().is_some())
            .finish()
    }
}

// Wire shape of a plugin: one type drives both deserialization and schema generation, so
// the two cannot describe different shapes. Plain `//` so this note stays out of the schema.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("oneOf" = plugin_source_one_of()))]
struct RawMitamaePlugin {
    /// Directory name the plugin is staged under, which is the name mitamae knows it by
    /// (`include_recipe 'docker'` finds `mitamae-plugin-recipe-docker`). Must start with
    /// `mitamae-plugin-resource-`, `mitamae-plugin-recipe-` or their `itamae-` forms.
    /// Defaults to the last component of `path`, the repository name of a git `url`, or
    /// the repository name before `/archive/` in an archive `url`.
    #[serde(default, deserialize_with = "crate::de::opt_string")]
    name: Option<String>,
    /// Plugin directory on the host (the checkout itself, holding `mrblib`). Relative paths
    /// are resolved against the profile's directory.
    #[serde(default, deserialize_with = "crate::de::opt_path")]
    #[schemars(with = "Option<crate::schema::Utf8PathSchema>")]
    path: Option<Utf8PathBuf>,
    /// Git repository (`https://`, `ssh://` or `user@host:path`) with `commit`, or an
    /// `https` URL of a `.tar.gz` / `.tar` archive with `checksum`.
    #[serde(default, deserialize_with = "crate::de::opt_string")]
    url: Option<String>,
    /// Full commit ID (40 or 64 hex digits) to take from the git repository `url`. Fetched
    /// with the host's `git`.
    #[serde(default, deserialize_with = "crate::de::opt_string")]
    commit: Option<String>,
    /// Expected digest of the archive at `url`, as `<algorithm>:<hex digest>` with
    /// algorithm `md5`, `sha1`, `sha256` or `sha512`, e.g. `sha256:9f86d0…`.
    #[serde(default)]
    checksum: Option<Checksum>,
}

// The schema's copy of the rule `MitamaePlugin::deserialize` enforces. The fields a branch
// does not use are pinned to `null` rather than forbidden, because the deserializer reads an
// explicit `null` as absent (see `schema::script_or_content`).
fn plugin_source_one_of() -> serde_json::Value {
    let text = serde_json::json!({ "type": "string" });
    let absent = serde_json::json!({ "type": "null" });
    serde_json::json!([
        {
            "required": ["path"],
            "properties": { "path": text, "url": absent, "commit": absent, "checksum": absent }
        },
        {
            "required": ["url", "commit"],
            "properties": { "url": text, "commit": text, "path": absent, "checksum": absent }
        },
        {
            "required": ["url", "checksum"],
            "properties": { "url": text, "checksum": text, "path": absent, "commit": absent }
        },
    ])
}

impl<'de> Deserialize<'de> for MitamaePlugin {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let raw = RawMitamaePlugin::deserialize(deserializer)?;
        let source = match (raw.path, raw.url, raw.commit, raw.checksum) {
            (Some(path), None, None, None) => MitamaePluginSource::Path(path),
            (None, Some(url), Some(commit), None) => MitamaePluginSource::Git { url, commit },
            (None, Some(url), None, Some(checksum)) => {
                MitamaePluginSource::Archive { url, checksum }
            }
            (Some(_), _, _, _) => {
                return Err(D::Error::custom(
                    "'path' cannot be combined with 'url', 'commit' or 'checksum'",
                ));
            }
            (None, Some(_), Some(_), Some(_)) => {
                return Err(D::Error::custom(
                    "'commit' (a git repository) and 'checksum' (an archive) \
                    are mutually exclusive",
                ));
            }
            (None, Some(_), None, None) => {
                return Err(D::Error::custom(
                    "'url' requires 'commit' (a git repository) or 'checksum' (an archive), \
                    so a changed upstream fails the build",
                ));
            }
            (None, None, _, _) => {
                return Err(D::Error::custom("one of 'path' or 'url' must be specified"));
            }
        };
        Ok(Self {
            name: raw.name,
            source,
            fetched: Arc::default(),
        })
    }
}

impl JsonSchema for MitamaePlugin {
    fn schema_name() -> Cow<'static, str> {
        "MitamaePlugin".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        RawMitamaePlugin::json_schema(generator)
    }
}

impl MitamaePlugin {
    fn from_source(source: MitamaePluginSource) -> Self {
        Self {
            name: None,
            source,
            fetched: Arc::default(),
        }
    }

    /// A plugin directory on the host.
    pub fn path(path: impl Into<Utf8PathBuf>) -> Self {
        Self::from_source(MitamaePluginSource::Path(path.into()))
    }

    /// A git repository at `commit`.
    pub fn git(url: impl Into<String>, commit: impl Into<String>) -> Self {
        Self::from_source(MitamaePluginSource::Git {
            url: url.into(),
            commit: commit.into(),
        })
    }

    /// A tar archive at an https `url`, pinned by `checksum`.
    pub fn archive(url: impl Into<String>, checksum: Checksum) -> Self {
        Self::from_source(MitamaePluginSource::Archive {
            url: url.into(),
            checksum,
        })
    }

    /// Sets the directory name the plugin is staged under.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Returns where the plugin comes from.
    pub fn source(&self) -> &MitamaePluginSource {
        &self.source
    }

    /// Returns the directory name the plugin is staged under: `name` if the profile gave
    /// one, otherwise the one derived from the source.
    pub fn name(&self) -> Result<String, RsdebstrapError> {
        let name = match &self.name {
            Some(name) => name.clone(),
            None => self.derived_name().ok_or_else(|| {
                RsdebstrapError::Validation(format!(
                    "cannot derive a name for mitamae plugin {}; set 'name'",
                    self.describe()
                ))
            })?,
        };
        let valid_chars = name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !valid_chars || !is_plugin_name(&name) {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae plugin name '{}' (from {}) must start with 'mitamae-plugin-resource-', \
                'mitamae-plugin-recipe-' or their 'itamae-' forms, and contain only letters, \
                digits, '.', '_' and '-'; mitamae ignores any other directory. Set 'name' to \
                override it",
                name,
                self.describe()
            )));
        }
        Ok(name)
    }

    fn derived_name(&self) -> Option<String> {
        match &self.source {
            MitamaePluginSource::Path(path) => path.file_name().map(str::to_owned),
            MitamaePluginSource::Git { url, .. } => {
                let last = url.trim_end_matches('/').rsplit(['/', ':']).next()?;
                Some(last.strip_suffix(".git").unwrap_or(last).to_owned())
            }
            MitamaePluginSource::Archive { url, .. } => {
                let parsed = url::Url::parse(url).ok()?;
                let segments: Vec<&str> = parsed.path_segments()?.collect();
                // `/<owner>/<repo>/archive/<ref>.tar.gz` (GitHub) and
                // `/<owner>/<repo>/-/archive/<ref>/<file>` (GitLab).
                if let Some(at) = segments.iter().position(|s| *s == "archive") {
                    return segments[..at]
                        .iter()
                        .rev()
                        .find(|s| **s != "-")
                        .map(|s| (*s).to_owned());
                }
                let file = segments.last()?;
                [".tar.gz", ".tgz", ".tar"]
                    .iter()
                    .find_map(|ext| file.strip_suffix(ext))
                    .map(str::to_owned)
            }
        }
    }

    fn describe(&self) -> String {
        match &self.source {
            MitamaePluginSource::Path(path) => format!("'{}'", path),
            MitamaePluginSource::Git { url, commit } => format!("'{}' at {}", url, commit),
            MitamaePluginSource::Archive { url, .. } => format!("'{}'", url),
        }
    }

    /// Resolves a relative `path` against `base_dir`.
    pub fn resolve_paths(&mut self, base_dir: &Utf8Path) {
        if let MitamaePluginSource::Path(path) = &mut self.source
            && path.is_relative()
        {
            *path = base_dir.join(&*path);
        }
    }

    /// Validates the declaration, then reads or fetches the plugin.
    ///
    /// Fetching here rather than when the task runs puts a download that fails, or a commit
    /// that does not exist, before the bootstrap instead of minutes after it. What was
    /// fetched is kept for staging, so the rootfs gets the bytes that were checked.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        self.name()?;
        let invalid = |msg: String| RsdebstrapError::Validation(format!("mitamae plugin {}", msg));
        match &self.source {
            MitamaePluginSource::Path(path) => {
                crate::phase::validate_no_parent_dirs(path, "mitamae plugin")?;
                crate::phase::validate_host_dir_exists(path, "mitamae plugin")?;
            }
            MitamaePluginSource::Git { url, commit } => {
                if !is_git_url(url) {
                    return Err(invalid(format!(
                        "url '{}' must be an https://, ssh:// or user@host:path git URL",
                        url
                    )));
                }
                if !(matches!(commit.len(), 40 | 64)
                    && commit.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err(invalid(format!(
                        "commit '{}' for '{}' must be a full commit ID (40 or 64 hex digits)",
                        commit, url
                    )));
                }
            }
            MitamaePluginSource::Archive { url, .. } => {
                let parsed = url::Url::parse(url)
                    .map_err(|e| invalid(format!("url '{}' is not a valid URL: {}", url, e)))?;
                if parsed.scheme() != "https" {
                    return Err(invalid(format!("url '{}' must use https", url)));
                }
            }
        }
        self.fetch()
            .map_err(|e| RsdebstrapError::Validation(format!("{:#}", e)))?;
        Ok(())
    }

    /// The plugin's `mrblib` tree, read or fetched on first use and kept from then on.
    fn fetch(&self) -> Result<Arc<PluginTree>> {
        if let Some(tree) = self.fetched.get() {
            return Ok(Arc::clone(tree));
        }
        let tree = Arc::new(match &self.source {
            MitamaePluginSource::Path(path) => {
                info!("reading mitamae plugin from {}", path);
                read_host_plugin(path)?
            }
            MitamaePluginSource::Git { url, commit } => {
                info!("fetching mitamae plugin from {} at {}", url, commit);
                fetch_git(url, &commit.to_ascii_lowercase())?
            }
            MitamaePluginSource::Archive { url, checksum } => {
                info!("downloading mitamae plugin from {}", url);
                let bytes = crate::https::get_to_vec(url, MAX_ARCHIVE_SIZE, "mitamae plugin")?;
                read_archive(&bytes, checksum, url)?
            }
        });
        Ok(Arc::clone(self.fetched.get_or_init(|| tree)))
    }
}

/// Validates a task's plugin list as a whole: each plugin, and that no two of them would be
/// staged under the same name -- mitamae would only ever see one of them.
pub(crate) fn validate_plugins(plugins: &[MitamaePlugin]) -> Result<(), RsdebstrapError> {
    let mut seen = std::collections::BTreeSet::new();
    for plugin in plugins {
        plugin.validate()?;
        let name = plugin.name()?;
        if !seen.insert(name.clone()) {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae plugin name '{}' is used more than once",
                name
            )));
        }
    }
    Ok(())
}

/// Whether mitamae reads anything from a plugins-directory entry named `name`.
///
/// mitamae globs `{,m}itamae-plugin-resource-*` and `{,m}itamae-plugin-recipe-*` there and
/// nothing else.
fn is_plugin_name(name: &str) -> bool {
    let name = name.strip_prefix('m').unwrap_or(name);
    name.starts_with("itamae-plugin-resource-") || name.starts_with("itamae-plugin-recipe-")
}

/// Whether `url` is a remote git URL this accepts: `https://`, `ssh://`, or the scp-like
/// `user@host:path`.
///
/// Local paths and `file://` are refused because `path:` covers them, and `ext::` and the
/// other transports git can be talked into are refused because they run commands. A leading
/// `-` can never get through, so the URL cannot be read as an option either.
fn is_git_url(url: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(url)
        && matches!(parsed.scheme(), "https" | "ssh")
    {
        return parsed.host_str().is_some_and(|h| !h.is_empty());
    }
    let Some((user_host, path)) = url.split_once(':') else {
        return false;
    };
    let Some((user, host)) = user_host.split_once('@') else {
        return false;
    };
    let word = |s: &str| {
        !s.is_empty()
            && !s.starts_with('-')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    word(user) && word(host) && !path.is_empty() && !path.starts_with('-')
}

// Every staged entry is one round-trip to the rootfs helper, and every entry is held in
// memory until it is written. A plugin pointed at the wrong place should fail here rather
// than stage a whole home directory.
const MAX_PLUGIN_ENTRIES: usize = 10_000;

// What one plugin may download. Plugin archives are a few hundred kilobytes; this is the
// limit a staged file already has.
const MAX_ARCHIVE_SIZE: u64 = crate::phase::MAX_STAGED_CONTENT_SIZE;

// What a plugin's tar stream may expand to, whether it came from an archive or from
// `git archive`. Bounds a decompression bomb, and a repository far larger than a plugin.
const MAX_UNPACKED_SIZE: u64 = 4 * MAX_ARCHIVE_SIZE;

/// One plugin's `mrblib` tree, as paths below the plugin's directory (`mrblib`,
/// `mrblib/x.rb`, ...) mapped to the file's content, or `None` for a directory.
///
/// Ordered by path, which puts every directory before what is in it: a parent's path is a
/// prefix of its children's, and a prefix sorts first.
#[derive(Debug, Default)]
struct PluginTree {
    entries: BTreeMap<String, Option<Vec<u8>>>,
    bytes: u64,
}

impl PluginTree {
    fn add_dir(&mut self, path: &str) -> Result<()> {
        if let Some(parent) = path.rsplit_once('/').map(|(parent, _)| parent) {
            self.add_dir(parent)?;
        }
        match self.entries.get(path) {
            Some(None) => Ok(()),
            Some(Some(_)) => Err(RsdebstrapError::Validation(format!(
                "mitamae plugin entry '{}' is both a file and a directory",
                path
            ))
            .into()),
            None => self.insert(path, None),
        }
    }

    fn add_file(&mut self, path: &str, content: Vec<u8>) -> Result<()> {
        if let Some((parent, _)) = path.rsplit_once('/') {
            self.add_dir(parent)?;
        }
        if self.entries.contains_key(path) {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae plugin entry '{}' appears more than once",
                path
            ))
            .into());
        }
        self.bytes += content.len() as u64;
        if self.bytes > crate::phase::MAX_STAGED_CONTENT_SIZE {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae plugin holds more than {} bytes in mrblib, refusing to stage it",
                crate::phase::MAX_STAGED_CONTENT_SIZE
            ))
            .into());
        }
        self.insert(path, Some(content))
    }

    fn insert(&mut self, path: &str, content: Option<Vec<u8>>) -> Result<()> {
        if self.entries.len() >= MAX_PLUGIN_ENTRIES {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae plugin holds more than {} entries in mrblib, refusing to stage it",
                MAX_PLUGIN_ENTRIES
            ))
            .into());
        }
        self.entries.insert(path.to_owned(), content);
        Ok(())
    }
}

/// Stages `plugins` into the rootfs as mitamae's plugins directory `base`.
///
/// Each plugin was read or fetched in full before this runs, so a plugin that fails leaves
/// nothing half-staged behind it.
pub(crate) fn stage_plugins(
    ops: &dyn RootfsOps,
    plugins: &[MitamaePlugin],
    base: &RelPath,
) -> Result<()> {
    let create_dir = |path: &RelPath| -> Result<()> {
        // Every directory here is new under a fresh UUID; one already there was put there
        // by something else, and writing into it would stage into a tree it controls.
        let created = ops
            .create_dir(path, FileMode::new(0o700))
            .with_context(|| format!("failed to stage mitamae plugins at {}", path))?;
        if !created {
            return Err(RsdebstrapError::Validation(format!(
                "refusing to stage mitamae plugins into {}: it already exists",
                path
            ))
            .into());
        }
        Ok(())
    };

    create_dir(base)?;
    for plugin in plugins {
        let name = plugin.name()?;
        let tree = plugin.fetch()?;
        info!("copying mitamae plugin {} ({} entries) to rootfs", name, tree.entries.len());
        create_dir(&RelPath::parse(&format!("{}/{}", base, name))?)?;
        for (rel, content) in &tree.entries {
            let path = RelPath::parse(&format!("{}/{}/{}", base, name, rel))?;
            match content {
                None => create_dir(&path)?,
                Some(content) => ops
                    .write_file(&path, content, FileMode::new(0o600))
                    .with_context(|| format!("failed to stage mitamae plugin file at {}", path))?,
            }
        }
    }
    Ok(())
}

/// Reads the `mrblib` tree of the plugin directory `dir` on the host.
///
/// Every directory is opened `O_NOFOLLOW` and every file read through the descriptor of the
/// directory it was listed in, as [`read_host_file`](crate::phase::read_host_file) does for
/// a single file. A symlink anywhere in it is refused rather than followed.
fn read_host_plugin(dir: &Utf8Path) -> Result<PluginTree> {
    let root = open_host_dir(rustix::fs::CWD, dir.as_str(), dir)?;
    let mrblib_path = dir.join("mrblib");
    let mrblib = open_host_dir(&root, "mrblib", &mrblib_path)?;
    let mut tree = PluginTree::default();
    tree.add_dir("mrblib")?;
    read_host_tree(&mut tree, &mrblib, "mrblib", &mrblib_path)?;
    Ok(tree)
}

fn read_host_tree(tree: &mut PluginTree, dir: &OwnedFd, rel: &str, path: &Utf8Path) -> Result<()> {
    use rustix::fs::FileType;

    for name in list_host_dir(dir, path)? {
        let child_rel = format!("{}/{}", rel, name);
        let child_path = path.join(&name);
        // Listed a moment ago; gone now is the tree changing under the walk.
        let Some(file_type) = host_entry_type(dir, &name, &child_path)? else {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae plugin entry {} disappeared while it was being read",
                child_path
            ))
            .into());
        };
        match file_type {
            FileType::Directory => {
                let child = open_host_dir(dir, &name, &child_path)?;
                tree.add_dir(&child_rel)?;
                read_host_tree(tree, &child, &child_rel, &child_path)?;
            }
            FileType::RegularFile => {
                let content = crate::phase::read_host_file_at(
                    dir,
                    &name,
                    &child_path,
                    "mitamae plugin file",
                )?;
                tree.add_file(&child_rel, content)?;
            }
            FileType::Symlink => {
                return Err(RsdebstrapError::Validation(format!(
                    "mitamae plugin path '{}' is a symlink, which is not allowed \
                    for security reasons",
                    child_path
                ))
                .into());
            }
            _ => {
                return Err(RsdebstrapError::Validation(format!(
                    "mitamae plugin path '{}' is neither a regular file nor a directory",
                    child_path
                ))
                .into());
            }
        }
    }
    Ok(())
}

/// The type of the entry `name` in `dir`, without following a symlink, or `None` if there
/// is no such entry.
fn host_entry_type(
    dir: impl AsFd,
    name: &str,
    path: &Utf8Path,
) -> Result<Option<rustix::fs::FileType>> {
    use rustix::fs::{self as rfs, AtFlags, FileType};

    match rfs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(FileType::from_raw_mode(stat.st_mode))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(e) => Err(RsdebstrapError::io(format!("failed to stat {}", path), e.into()).into()),
    }
}

/// Opens the directory `name` in `dir`, refusing a symlink or anything that is not a
/// directory.
fn open_host_dir(dir: impl AsFd, name: &str, path: &Utf8Path) -> Result<OwnedFd> {
    use rustix::fs::{self as rfs, FileType, Mode, OFlags};

    // Checked first only for the message: `O_DIRECTORY` reports a symlink as `ENOTDIR`, the
    // same as a file. The open below is what refuses either.
    match host_entry_type(dir.as_fd(), name, path)? {
        Some(FileType::Symlink) => {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae plugin path '{}' is a symlink, which is not allowed \
                for security reasons",
                path
            ))
            .into());
        }
        Some(FileType::Directory) => {}
        Some(_) => {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae plugin path is not a directory: {}",
                path
            ))
            .into());
        }
        None => {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae plugin path not found: {}",
                path
            ))
            .into());
        }
    }
    rfs::openat(
        dir,
        name,
        OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| RsdebstrapError::io(format!("failed to open {}", path), e.into()).into())
}

/// The names in `dir`, sorted so what is staged does not depend on directory order.
fn list_host_dir(dir: &OwnedFd, path: &Utf8Path) -> Result<Vec<String>> {
    let list_err = |e: rustix::io::Errno| -> anyhow::Error {
        RsdebstrapError::io(format!("failed to list {}", path), e.into()).into()
    };
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(dir).map_err(list_err)? {
        let entry = entry.map_err(list_err)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(bytes).map_err(|_| {
            RsdebstrapError::Validation(format!(
                "mitamae plugin entry in {} has a name that is not valid UTF-8: {:?}",
                path,
                String::from_utf8_lossy(bytes)
            ))
        })?;
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

/// Checks a downloaded archive against `checksum` and reads its `mrblib` tree.
///
/// The archive may be gzip-compressed or a plain tar; the gzip magic decides, not the URL.
fn read_archive(bytes: &[u8], checksum: &Checksum, url: &str) -> Result<PluginTree> {
    checksum
        .verify(bytes)
        .map_err(|e| RsdebstrapError::Validation(format!("mitamae plugin {}: {}", url, e)))?;
    if bytes.starts_with(&[0x1f, 0x8b]) {
        read_tar(flate2::read::GzDecoder::new(bytes), url)
    } else {
        read_tar(bytes, url)
    }
}

/// A reader that fails once more than `limit` bytes have come through it.
///
/// `Read::take` would end the stream quietly instead, and the tar parser would report a
/// truncated archive rather than the limit.
struct LimitedReader<R> {
    inner: R,
    limit: u64,
    remaining: u64,
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.remaining = self.remaining.checked_sub(n as u64).ok_or_else(|| {
            std::io::Error::other(format!("unpacks to more than {} bytes", self.limit))
        })?;
        Ok(n)
    }
}

/// What a tar member is, as far as staging it is concerned.
enum TarMember {
    Dir,
    File(Vec<u8>),
    /// A symlink, hard link or device: refused if it is inside `mrblib`, ignored elsewhere.
    Other(&'static str),
}

/// Reads the `mrblib` tree out of a tar stream.
///
/// `mrblib` is looked for at the top of the archive, and failing that inside its single
/// top-level directory -- the `<repo>-<ref>/` a forge's archive download wraps everything in.
/// Every member path must be relative and free of `..`, wherever it is; members outside
/// `mrblib` are then ignored, and inside it only directories and regular files are accepted.
fn read_tar(reader: impl Read, source: &str) -> Result<PluginTree> {
    read_tar_limited(reader, source, MAX_UNPACKED_SIZE)
}

fn read_tar_limited(reader: impl Read, source: &str, limit: u64) -> Result<PluginTree> {
    use tar::EntryType;

    let mut archive = tar::Archive::new(LimitedReader {
        inner: reader,
        limit,
        remaining: limit,
    });
    let read_err = |e: std::io::Error| -> anyhow::Error {
        anyhow::Error::new(e).context(format!("failed to read mitamae plugin {}", source))
    };

    let mut members: Vec<(Vec<String>, TarMember)> = Vec::new();
    for entry in archive.entries().map_err(read_err)? {
        let mut entry = entry.map_err(read_err)?;
        let kind = entry.header().entry_type();
        if matches!(kind, EntryType::XGlobalHeader | EntryType::XHeader) {
            continue;
        }
        if members.len() >= MAX_PLUGIN_ENTRIES {
            return Err(RsdebstrapError::Validation(format!(
                "mitamae plugin {} holds more than {} entries, refusing to read it",
                source, MAX_PLUGIN_ENTRIES
            ))
            .into());
        }
        let raw_path = entry.path_bytes().into_owned();
        let path = std::str::from_utf8(&raw_path).map_err(|_| {
            RsdebstrapError::Validation(format!(
                "mitamae plugin {} has a member whose name is not valid UTF-8: {:?}",
                source,
                String::from_utf8_lossy(&raw_path)
            ))
        })?;
        let components = tar_components(path).ok_or_else(|| {
            RsdebstrapError::Validation(format!(
                "mitamae plugin {} has a member outside the archive: '{}'",
                source, path
            ))
        })?;
        if components.is_empty() {
            continue;
        }
        let member = match kind {
            EntryType::Directory => TarMember::Dir,
            EntryType::Regular | EntryType::Continuous => {
                let mut content = Vec::new();
                entry.read_to_end(&mut content).map_err(read_err)?;
                TarMember::File(content)
            }
            EntryType::Symlink => TarMember::Other("a symlink"),
            EntryType::Link => TarMember::Other("a hard link"),
            _ => TarMember::Other("neither a regular file nor a directory"),
        };
        members.push((components, member));
    }

    let at_top = members.iter().any(|(c, _)| c[0] == "mrblib");
    let prefix: Vec<String> = if at_top {
        vec!["mrblib".to_owned()]
    } else {
        let top = members.first().map(|(c, _)| c[0].clone());
        match top {
            Some(top) if members.iter().all(|(c, _)| c[0] == top) => {
                vec![top, "mrblib".to_owned()]
            }
            _ => Vec::new(),
        }
    };
    let mut tree = PluginTree::default();
    for (components, member) in members {
        if prefix.is_empty() || !components.starts_with(&prefix) {
            continue;
        }
        let rel = std::iter::once("mrblib")
            .chain(components[prefix.len()..].iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join("/");
        match member {
            TarMember::Dir => tree.add_dir(&rel)?,
            TarMember::File(_) if components.len() == prefix.len() => {
                return Err(RsdebstrapError::Validation(format!(
                    "mitamae plugin {}: '{}' is a file, not a directory",
                    source,
                    components.join("/")
                ))
                .into());
            }
            TarMember::File(content) => tree.add_file(&rel, content)?,
            TarMember::Other(what) => {
                return Err(RsdebstrapError::Validation(format!(
                    "mitamae plugin {}: '{}' is {}, which is not allowed in mrblib",
                    source,
                    components.join("/"),
                    what
                ))
                .into());
            }
        }
    }
    if tree.entries.is_empty() {
        return Err(RsdebstrapError::Validation(format!(
            "mitamae plugin {} has no mrblib directory, at its top or inside a single \
            top-level directory",
            source
        ))
        .into());
    }
    Ok(tree)
}

/// The components of a tar member path, or `None` if it is absolute or climbs with `..`.
fn tar_components(path: &str) -> Option<Vec<String>> {
    if path.starts_with('/') {
        return None;
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => return None,
            other => components.push(other.to_owned()),
        }
    }
    Some(components)
}

/// Fetches `commit` from the git repository `url` with the host's `git` and reads its
/// `mrblib` tree.
///
/// The commit is fetched into a scratch bare repository and read back as a `git archive`
/// tar stream, so nothing is checked out and the same tar reading -- and refusals -- apply
/// as to a downloaded archive. Fetching by object ID is what pins the content: git verifies
/// what it receives against the ID.
fn fetch_git(url: &str, commit: &str) -> Result<PluginTree> {
    let scratch = tempfile::tempdir().context("failed to create a scratch git repository")?;
    let repo = Utf8Path::from_path(scratch.path())
        .ok_or_else(|| anyhow::anyhow!("scratch directory is not UTF-8: {:?}", scratch.path()))?;
    let source = format!("{} at {}", url, commit);

    run_git(repo, &["init", "--bare", "--quiet", "."], &source)?;
    // A shallow fetch of the one commit is enough, but a server can refuse a `want` for an
    // object no ref points at. Fetching every branch and tag, then looking for the commit
    // among them, works against any server.
    let shallow = run_git(
        repo,
        &[
            "fetch",
            "--quiet",
            "--depth=1",
            "--no-tags",
            "--no-recurse-submodules",
            "--end-of-options",
            url,
            commit,
        ],
        &source,
    );
    if let Err(e) = shallow {
        debug!("fetching {} by commit failed, fetching all refs instead: {:#}", source, e);
        run_git(
            repo,
            &[
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                "--end-of-options",
                url,
                "+refs/heads/*:refs/heads/*",
                "+refs/tags/*:refs/tags/*",
            ],
            &source,
        )?;
    }
    run_git(repo, &["cat-file", "-e", &format!("{}^{{commit}}", commit)], &source).map_err(
        |_| RsdebstrapError::Validation(format!("mitamae plugin {}: commit not found", source)),
    )?;

    let mut child = git_command(repo)
        .args(["archive", "--format=tar", commit])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| git_spawn_error(e, &source))?;
    let stdout = child.stdout.take().expect("stdout is piped");
    let tree = read_tar(stdout, &source);
    if tree.is_err() {
        // Stopped reading early; without this `git archive` blocks on a full pipe.
        let _ = child.kill();
    }
    let output = child
        .wait_with_output()
        .with_context(|| format!("failed to wait for git archive of {}", source))?;
    let tree = tree?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "git archive of {} failed ({}): {}",
            source,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(tree)
}

fn git_command(repo: &Utf8Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo.as_str())
        // A git that cannot authenticate otherwise would stop to ask on the terminal, which
        // in the middle of a build is a hang.
        .env("GIT_TERMINAL_PROMPT", "0")
        // An inherited repository location would point every command here at another one.
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .stdin(Stdio::null());
    command
}

fn run_git(repo: &Utf8Path, args: &[&str], source: &str) -> Result<()> {
    let output = git_command(repo)
        .args(args)
        .output()
        .map_err(|e| git_spawn_error(e, source))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "git {} for mitamae plugin {} failed ({}): {}",
            args[0],
            source,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn git_spawn_error(e: std::io::Error, source: &str) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        RsdebstrapError::Validation(format!(
            "mitamae plugin {} is a git repository, which needs git on the host; \
            git was not found",
            source
        ))
        .into()
    } else {
        anyhow::Error::new(e).context(format!("failed to run git for mitamae plugin {}", source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::Algorithm;

    enum Member<'a> {
        Dir(&'a str),
        File(&'a str, &'a str),
        Symlink(&'a str, &'a str),
    }

    // Builds a tar, with a pax global header first as `git archive` and forge downloads
    // write one. Paths are written into the header raw, because `tar::Builder`'s own path
    // setters refuse `..` -- which is what some of these archives must contain.
    fn tar(members: &[Member]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut pax = tar::Header::new_ustar();
        pax.set_entry_type(tar::EntryType::XGlobalHeader);
        let comment = b"52 comment=5217372e85df6c94f0a1dec05c7739114b35d570\n";
        pax.set_size(comment.len() as u64);
        pax.set_cksum();
        builder.append(&pax, &comment[..]).unwrap();
        for member in members {
            let mut header = tar::Header::new_ustar();
            let (path, kind, data): (&str, _, &[u8]) = match member {
                Member::Dir(path) => (path, tar::EntryType::Directory, b""),
                Member::File(path, content) => (path, tar::EntryType::Regular, content.as_bytes()),
                Member::Symlink(path, target) => {
                    header.set_link_name(target).unwrap();
                    (path, tar::EntryType::Symlink, b"")
                }
            };
            header.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
            header.set_entry_type(kind);
            header.set_mode(0o644);
            header.set_size(data.len() as u64);
            header.set_cksum();
            builder.append(&header, data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn read(archive: &[u8]) -> Result<Vec<(String, Option<String>)>> {
        let tree = read_archive(archive, &Checksum::of(Algorithm::Sha256, archive), "test")?;
        Ok(tree
            .entries
            .into_iter()
            .map(|(path, content)| (path, content.map(|c| String::from_utf8(c).unwrap())))
            .collect())
    }

    fn message(err: anyhow::Error) -> String {
        format!("{:#}", err)
    }

    #[test]
    fn reads_mrblib_from_inside_a_forge_style_top_level_directory() {
        // The shape of github.com/<owner>/<repo>/archive/<commit>.tar.gz. The symlink outside
        // mrblib is ignored along with everything else there; it is never staged.
        let archive = gzip(&tar(&[
            Member::Dir("repo-5217372/"),
            Member::File("repo-5217372/README.md", "readme"),
            Member::Symlink("repo-5217372/link", "/etc/passwd"),
            Member::Dir("repo-5217372/mrblib/"),
            Member::File("repo-5217372/mrblib/a.rb", "a"),
            // No directory member for `sub`, as tar allows: it is created anyway.
            Member::File("repo-5217372/mrblib/sub/b.rb", "b"),
        ]));
        assert_eq!(
            read(&archive).unwrap(),
            vec![
                ("mrblib".to_string(), None),
                ("mrblib/a.rb".to_string(), Some("a".to_string())),
                ("mrblib/sub".to_string(), None),
                ("mrblib/sub/b.rb".to_string(), Some("b".to_string())),
            ]
        );
    }

    #[test]
    fn reads_mrblib_at_the_top_of_an_uncompressed_tar() {
        let archive = tar(&[
            Member::File("./mrblib/a.rb", "a"),
            Member::File("LICENSE", "l"),
        ]);
        assert_eq!(
            read(&archive).unwrap(),
            vec![
                ("mrblib".to_string(), None),
                ("mrblib/a.rb".to_string(), Some("a".to_string())),
            ]
        );
    }

    #[test]
    fn refuses_a_checksum_mismatch() {
        let archive = gzip(&tar(&[Member::File("mrblib/a.rb", "a")]));
        let other = Checksum::of(Algorithm::Sha256, b"other");
        let err = read_archive(&archive, &other, "test").unwrap_err();
        assert!(message(err).contains("checksum mismatch"));
    }

    #[test]
    fn refuses_a_symlink_inside_mrblib() {
        let archive = tar(&[Member::Symlink("mrblib/evil.rb", "/etc/shadow")]);
        let err = message(read(&archive).unwrap_err());
        assert!(err.contains("mrblib/evil.rb") && err.contains("symlink"), "{}", err);
    }

    #[test]
    fn refuses_a_member_that_climbs_out_even_outside_mrblib() {
        let archive = tar(&[
            Member::File("mrblib/a.rb", "a"),
            Member::File("x/../../y", "y"),
        ]);
        let err = message(read(&archive).unwrap_err());
        assert!(err.contains("outside the archive"), "{}", err);
    }

    #[test]
    fn refuses_an_archive_without_mrblib() {
        let archive = tar(&[
            Member::File("a/lib/a.rb", "a"),
            Member::File("b/README", "b"),
        ]);
        let err = message(read(&archive).unwrap_err());
        assert!(err.contains("no mrblib"), "{}", err);
    }

    #[test]
    fn refuses_an_archive_that_unpacks_past_the_limit() {
        // Zeros compress to almost nothing; the limit is on what comes out.
        let archive = gzip(&tar(&[Member::File("outside", &"\0".repeat(64 << 10))]));
        let decoder = flate2::read::GzDecoder::new(&archive[..]);
        let err = message(read_tar_limited(decoder, "test", 32 << 10).unwrap_err());
        assert!(err.contains("unpacks to more than"), "{}", err);
    }

    #[test]
    fn accepts_only_remote_git_urls() {
        for url in [
            "https://github.com/o/r.git",
            "ssh://git@github.com/o/r.git",
            "git@github.com:o/r.git",
        ] {
            assert!(is_git_url(url), "{} should be accepted", url);
        }
        for url in [
            "http://github.com/o/r.git",
            "file:///srv/r.git",
            "/srv/r.git",
            "./r",
            "ext::sh -c id",
            "-uhttps://x",
            "git@-oProxyCommand=x:r",
            "git@host:-r",
        ] {
            assert!(!is_git_url(url), "{} should be refused", url);
        }
    }
}
