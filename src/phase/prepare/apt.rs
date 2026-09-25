//! apt task implementation for the prepare phase.
//!
//! This module provides the [`AptTask`] data structure declaring OpenPGP keyrings, APT
//! repositories — deb822 `.sources` files that may name one of those keyrings in their
//! `Signed-By` — and APT preferences (pins) that provisioning should see. Like the other
//! prepare tasks it only declares: the files are written and, unless an entry says
//! `keep: true`, removed again by a guard at the pipeline level (`isolation::apt_sources`),
//! after provisioning and before assemble.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use camino::{Utf8Path, Utf8PathBuf};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

use crate::error::RsdebstrapError;
use crate::phase::PhaseItem;
use crate::rootfs::RelPath;

/// Directory the generated `.sources` files are written to.
const SOURCES_DIR: &str = "/etc/apt/sources.list.d";

/// Directory the generated preferences files are written to.
const PREFERENCES_DIR: &str = "/etc/apt/preferences.d";

/// Directory keyrings are written to, created when the rootfs does not have it.
///
/// Not `/etc/apt/trusted.gpg.d`: a key there is trusted for every repository, and the point
/// of `Signed-By` is that a keyring vouches for the repositories that name it only.
pub(crate) const KEYRINGS_DIR: &str = "/etc/apt/keyrings";

/// Refuses a keyring larger than this, whichever source it comes from.
///
/// An OpenPGP public key with a handful of subkeys is a few kilobytes; anything near this is
/// not the file the profile meant. It bounds the download in particular, where the size is
/// the server's to choose.
pub(crate) const MAX_KEY_SIZE: u64 = 1 << 20;

/// apt task declaring keyrings, APT repositories and APT preferences for the prepare phase.
///
/// At most one `AptTask` may appear in the prepare phase.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AptTask {
    /// OpenPGP keyrings to install. Each one is written to `/etc/apt/keyrings/<name>.asc`
    /// (ASCII-armored) or `<name>.gpg` (binary); `/etc/apt/keyrings` is created if the
    /// rootfs has none. A repository uses one by naming it in `signed_by`.
    #[serde(
        default,
        deserialize_with = "crate::de::null_to_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schemars(with = "Option<Vec<AptKeyring>>")]
    pub keyrings: Vec<AptKeyring>,
    /// APT repositories to configure before provisioning. Each one is written to
    /// `/etc/apt/sources.list.d/<name>.sources` in deb822 format.
    #[serde(
        default,
        deserialize_with = "crate::de::null_to_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schemars(with = "Option<Vec<AptRepository>>")]
    pub repositories: Vec<AptRepository>,
    /// APT preferences to apply before provisioning. Each one is written to
    /// `/etc/apt/preferences.d/<name>.pref` (see apt_preferences(5)).
    #[serde(
        default,
        deserialize_with = "crate::de::null_to_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schemars(with = "Option<Vec<AptPreference>>")]
    pub preferences: Vec<AptPreference>,
}

/// One APT preferences file, holding one stanza per pin.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AptPreference {
    /// File name stem for the preferences file. Letters, digits, `_`, `-` and `.` only (what
    /// apt reads from `preferences.d`), unique within `preferences`.
    #[serde(deserialize_with = "crate::de::string")]
    pub name: String,
    /// The pins, written as stanzas in this order.
    pub pins: Vec<AptPin>,
    /// Keep the preferences file in the final rootfs. When `false` (the default) it is
    /// removed after provisioning and before assemble, and whatever was at that path before
    /// is put back.
    #[serde(default)]
    pub keep: bool,
}

/// One apt_preferences(5) stanza.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AptPin {
    /// `Package`: package names, glob patterns, `/regex/`, or `src:` names; `*` for every
    /// package.
    #[serde(deserialize_with = "crate::de::string_list")]
    #[schemars(with = "Vec<String>")]
    pub packages: Vec<String>,
    /// `Pin`: what the priority applies to, starting with `release`, `origin` or `version`
    /// (e.g. `release n=trixie-backports`, `origin "download.docker.com"`, `version 5.8*`).
    #[serde(deserialize_with = "crate::de::string")]
    pub pin: String,
    /// `Pin-Priority`. Must not be zero: apt ignores a pin with priority 0.
    pub priority: i32,
    /// `Explanation`: a one-line comment for the stanza.
    #[serde(
        default,
        deserialize_with = "crate::de::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub explanation: Option<String>,
}

/// One APT repository, rendered as a deb822 `.sources` file.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AptRepository {
    /// File name stem for the `.sources` file. Letters, digits, `_`, `-` and `.` only (what
    /// apt reads from `sources.list.d`), unique within `repositories`.
    #[serde(deserialize_with = "crate::de::string")]
    pub name: String,
    /// deb822 `Types` (default: `[deb]`).
    #[serde(default = "default_types")]
    pub types: Vec<AptSourceType>,
    /// deb822 `URIs`: repository base URIs.
    #[serde(deserialize_with = "crate::de::string_list")]
    #[schemars(with = "Vec<String>")]
    pub uris: Vec<String>,
    /// deb822 `Suites`. A suite ending in `/` is an exact path, which takes no
    /// `components`.
    #[serde(deserialize_with = "crate::de::string_list")]
    #[schemars(with = "Vec<String>")]
    pub suites: Vec<String>,
    /// deb822 `Components`. Required unless every suite is an exact path.
    #[serde(
        default,
        deserialize_with = "crate::de::string_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schemars(with = "Option<Vec<String>>")]
    pub components: Vec<String>,
    /// deb822 `Architectures`. Omitted from the file when empty, so apt uses its
    /// configured architectures.
    #[serde(
        default,
        deserialize_with = "crate::de::string_list",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[schemars(with = "Option<Vec<String>>")]
    pub architectures: Vec<String>,
    /// Name of an entry in `keyrings` to write as this repository's `Signed-By`. Without
    /// it, apt verifies against the keys it already trusts.
    #[serde(
        default,
        deserialize_with = "crate::de::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub signed_by: Option<String>,
    /// Keep the repository in the final rootfs. When `false` (the default) its file is
    /// removed after provisioning and before assemble, and whatever was at that path before
    /// is put back. A kept repository's keyring must be kept too.
    #[serde(default)]
    pub keep: bool,
}

fn default_types() -> Vec<AptSourceType> {
    vec![AptSourceType::Deb]
}

/// deb822 `Types` value.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, JsonSchema)]
pub enum AptSourceType {
    /// Binary packages.
    #[serde(rename = "deb")]
    Deb,
    /// Source packages.
    #[serde(rename = "deb-src")]
    DebSrc,
}

impl AptSourceType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Deb => "deb",
            Self::DebSrc => "deb-src",
        }
    }
}

/// Where a keyring comes from: exactly one of `path`, `content` or `url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AptKeySource {
    /// A key file on the host.
    Path(Utf8PathBuf),
    /// The key inline in the profile (ASCII-armored).
    Content(String),
    /// An `https` URL the key is downloaded from when the prepare phase runs.
    Url(String),
}

/// One OpenPGP keyring, written to `/etc/apt/keyrings`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptKeyring {
    pub name: String,
    pub source: AptKeySource,
    /// Lowercase hex SHA-256 of the key's bytes.
    pub sha256: Option<String>,
    pub keep: bool,
}

// Wire shape of a keyring: one type drives both deserialization and schema generation, so
// the two cannot describe different shapes. Plain `//` so this note stays out of the schema.
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("oneOf" = key_source_one_of()))]
struct RawAptKeyring {
    /// File name stem for the keyring, and what a repository's `signed_by` names. Letters,
    /// digits, `_`, `-` and `.` only, unique within `keyrings`.
    #[serde(deserialize_with = "crate::de::string")]
    name: String,
    /// Path to a key file on the host (ASCII-armored or binary). Relative paths are
    /// resolved against the profile's directory.
    #[serde(
        default,
        deserialize_with = "crate::de::opt_path",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Option<crate::schema::Utf8PathSchema>")]
    path: Option<Utf8PathBuf>,
    /// The key inline, ASCII-armored (`-----BEGIN PGP PUBLIC KEY BLOCK-----`).
    #[serde(
        default,
        deserialize_with = "crate::de::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    content: Option<String>,
    /// `https` URL to download the key from while the prepare phase runs.
    #[serde(
        default,
        deserialize_with = "crate::de::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    url: Option<String>,
    /// Expected SHA-256 of the key's bytes, as 64 hex digits. Checked before anything is
    /// written; recommended with `url`, where the bytes are the server's to choose.
    #[serde(
        default,
        deserialize_with = "crate::de::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    sha256: Option<String>,
    /// Keep the keyring in the final rootfs. When `false` (the default) it is removed after
    /// provisioning and before assemble, and whatever was at that path before is put back.
    #[serde(default)]
    keep: bool,
}

// The schema's copy of the rule `AptKeyring::deserialize` enforces. Each branch pins its
// field to a string, for the reason `schema::script_or_content` gives.
fn key_source_one_of() -> serde_json::Value {
    serde_json::json!([
        { "required": ["path"], "properties": { "path": { "type": "string" } } },
        { "required": ["content"], "properties": { "content": { "type": "string" } } },
        { "required": ["url"], "properties": { "url": { "type": "string" } } },
    ])
}

impl<'de> Deserialize<'de> for AptKeyring {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawAptKeyring::deserialize(deserializer)?;
        let source = match (raw.path, raw.content, raw.url) {
            (Some(path), None, None) => AptKeySource::Path(path),
            (None, Some(content), None) => AptKeySource::Content(content),
            (None, None, Some(url)) => AptKeySource::Url(url),
            (None, None, None) => {
                return Err(serde::de::Error::custom(
                    "one of 'path', 'content' or 'url' must be specified",
                ));
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "'path', 'content' and 'url' are mutually exclusive",
                ));
            }
        };
        Ok(Self {
            name: raw.name,
            source,
            sha256: raw.sha256,
            keep: raw.keep,
        })
    }
}

impl Serialize for AptKeyring {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (path, content, url) = match &self.source {
            AptKeySource::Path(p) => (Some(p.clone()), None, None),
            AptKeySource::Content(c) => (None, Some(c.clone()), None),
            AptKeySource::Url(u) => (None, None, Some(u.clone())),
        };
        RawAptKeyring {
            name: self.name.clone(),
            path,
            content,
            url,
            sha256: self.sha256.clone(),
            keep: self.keep,
        }
        .serialize(serializer)
    }
}

impl JsonSchema for AptKeyring {
    fn schema_name() -> Cow<'static, str> {
        "AptKeyring".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        RawAptKeyring::json_schema(generator)
    }
}

/// The two encodings apt accepts for a `Signed-By` keyring, told apart by file extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyFormat {
    Armored,
    Binary,
}

impl KeyFormat {
    /// Identifies an OpenPGP *public* key by its first bytes.
    ///
    /// Only enough to pick the extension apt dispatches on, and to refuse what is plainly not
    /// a public key — an HTML error page served with a 200, or a secret key pasted by
    /// mistake — before it is installed as a trust anchor. It does not parse the key.
    pub(crate) fn detect(bytes: &[u8]) -> Result<Self, RsdebstrapError> {
        let text = bytes.trim_ascii_start();
        if text.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----") {
            return Ok(Self::Armored);
        }
        // A binary keyring starts with a Public-Key packet (tag 6): 0xC6 in the new packet
        // format, 0x98..=0x9B in the old one, whose low two bits are the length type.
        match bytes.first() {
            Some(0xC6 | 0x98..=0x9B) => Ok(Self::Binary),
            _ => Err(RsdebstrapError::Validation(
                "not an OpenPGP public key: expected an ASCII-armored \
                '-----BEGIN PGP PUBLIC KEY BLOCK-----' or a binary keyring"
                    .to_string(),
            )),
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Armored => "asc",
            Self::Binary => "gpg",
        }
    }
}

/// Refuses a name apt would skip in its directories -- the entry would silently not be
/// there -- or one that is not a single path component.
fn validate_name(kind: &str, name: &str) -> Result<(), RsdebstrapError> {
    if name.is_empty()
        || name.starts_with('.')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(RsdebstrapError::Validation(format!(
            "apt {} name {:?} must be non-empty, not start with '.', and contain only \
            letters, digits, '_', '-' and '.'",
            kind, name
        )));
    }
    Ok(())
}

impl AptTask {
    /// Resolves relative keyring paths against `base_dir` (the profile's directory).
    pub fn resolve_paths(&mut self, base_dir: &Utf8Path) {
        for keyring in &mut self.keyrings {
            if let AptKeySource::Path(path) = &mut keyring.source
                && path.is_relative()
            {
                *path = base_dir.join(&*path);
            }
        }
    }

    /// Validates every entry, that names are unique, and that each `signed_by` names a
    /// keyring that lives at least as long as the repository.
    pub fn validate(&self) -> Result<(), RsdebstrapError> {
        if self.keyrings.is_empty() && self.repositories.is_empty() && self.preferences.is_empty() {
            return Err(RsdebstrapError::Validation(
                "apt must declare at least one keyring, repository or preference".to_string(),
            ));
        }

        let mut keyrings = HashMap::new();
        for keyring in &self.keyrings {
            keyring.validate()?;
            if keyrings.insert(keyring.name.as_str(), keyring).is_some() {
                return Err(RsdebstrapError::Validation(format!(
                    "apt keyring name '{}' is used more than once",
                    keyring.name
                )));
            }
        }

        let mut names = HashSet::new();
        for repo in &self.repositories {
            repo.validate()?;
            if !names.insert(repo.name.as_str()) {
                return Err(RsdebstrapError::Validation(format!(
                    "apt repository name '{}' is used more than once",
                    repo.name
                )));
            }
            let Some(signed_by) = &repo.signed_by else {
                continue;
            };
            let Some(keyring) = keyrings.get(signed_by.as_str()) else {
                return Err(RsdebstrapError::Validation(format!(
                    "apt repository '{}': signed_by '{}' names no entry in keyrings",
                    repo.name, signed_by
                )));
            };
            // The final rootfs would name a keyring in `Signed-By` that is no longer
            // there, and `apt-get update` fails on it for everyone who uses the image.
            if repo.keep && !keyring.keep {
                return Err(RsdebstrapError::Validation(format!(
                    "apt repository '{}' is kept, so its keyring '{}' must be kept too",
                    repo.name, keyring.name
                )));
            }
        }

        let mut names = HashSet::new();
        for preference in &self.preferences {
            preference.validate()?;
            if !names.insert(preference.name.as_str()) {
                return Err(RsdebstrapError::Validation(format!(
                    "apt preference name '{}' is used more than once",
                    preference.name
                )));
            }
        }
        Ok(())
    }
}

impl AptRepository {
    /// Where this repository's `.sources` file is written.
    pub(crate) fn sources_path(&self) -> RelPath {
        RelPath::parse(&format!("{}/{}.sources", SOURCES_DIR, self.name))
            .expect("a validated repository name forms a single path component")
    }

    /// Renders the deb822 `.sources` file, naming `signed_by` as its keyring if given.
    pub(crate) fn render_sources(&self, signed_by: Option<&RelPath>) -> String {
        let mut lines = vec!["# Generated by rsdebstrap".to_string()];
        let types: Vec<&str> = self.types.iter().map(|t| t.as_str()).collect();
        lines.push(format!("Types: {}", types.join(" ")));
        lines.push(format!("URIs: {}", self.uris.join(" ")));
        lines.push(format!("Suites: {}", self.suites.join(" ")));
        if !self.components.is_empty() {
            lines.push(format!("Components: {}", self.components.join(" ")));
        }
        if !self.architectures.is_empty() {
            lines.push(format!("Architectures: {}", self.architectures.join(" ")));
        }
        if let Some(path) = signed_by {
            lines.push(format!("Signed-By: {}", path));
        }
        lines.join("\n") + "\n"
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        validate_name("repository", &self.name)?;
        let invalid = |msg: String| {
            Err(RsdebstrapError::Validation(format!("apt repository '{}': {}", self.name, msg)))
        };

        if self.types.is_empty() {
            return invalid("types must not be empty".to_string());
        }
        for (field, values) in [
            ("uris", &self.uris),
            ("suites", &self.suites),
            ("components", &self.components),
            ("architectures", &self.architectures),
        ] {
            // deb822 separates the values of a field by whitespace, so a value holding any
            // would be read back as two -- or, with a newline, as a field of its own.
            if let Some(value) = values
                .iter()
                .find(|v| v.is_empty() || v.chars().any(|c| c.is_whitespace() || c.is_control()))
            {
                return invalid(format!(
                    "{} entry {:?} is empty or contains whitespace",
                    field, value
                ));
            }
        }
        if self.uris.is_empty() {
            return invalid("uris must not be empty".to_string());
        }
        for uri in &self.uris {
            if let Err(e) = url::Url::parse(uri) {
                return invalid(format!("uri '{}' is not a valid URI: {}", uri, e));
            }
        }
        if self.suites.is_empty() {
            return invalid("suites must not be empty".to_string());
        }
        let exact = self.suites.iter().filter(|s| s.ends_with('/')).count();
        if exact > 0 && exact < self.suites.len() {
            return invalid(
                "suites must be all exact paths (ending in '/') or none of them".to_string(),
            );
        }
        match (exact > 0, self.components.is_empty()) {
            (true, false) => {
                invalid("an exact-path suite (ending in '/') takes no components".to_string())
            }
            (false, true) => invalid("components must not be empty".to_string()),
            _ => Ok(()),
        }
    }
}

impl AptPreference {
    /// Where this preferences file is written.
    ///
    /// apt reads a file in `preferences.d` only if it has no extension or `.pref`, so a name
    /// containing `.` would be skipped without the extension.
    pub(crate) fn preferences_path(&self) -> RelPath {
        RelPath::parse(&format!("{}/{}.pref", PREFERENCES_DIR, self.name))
            .expect("a validated preference name forms a single path component")
    }

    /// Renders the preferences file, one stanza per pin, separated by blank lines.
    pub(crate) fn render(&self) -> String {
        let stanzas: Vec<String> = self
            .pins
            .iter()
            .map(|pin| {
                let mut lines = Vec::new();
                if let Some(explanation) = &pin.explanation {
                    lines.push(format!("Explanation: {}", explanation));
                }
                lines.push(format!("Package: {}", pin.packages.join(" ")));
                lines.push(format!("Pin: {}", pin.pin));
                lines.push(format!("Pin-Priority: {}", pin.priority));
                lines.join("\n") + "\n"
            })
            .collect();
        format!("# Generated by rsdebstrap\n{}", stanzas.join("\n"))
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        validate_name("preference", &self.name)?;
        if self.pins.is_empty() {
            return Err(RsdebstrapError::Validation(format!(
                "apt preference '{}': pins must not be empty",
                self.name
            )));
        }
        for (i, pin) in self.pins.iter().enumerate() {
            pin.validate().map_err(|msg| {
                RsdebstrapError::Validation(format!(
                    "apt preference '{}': pins[{}]: {}",
                    self.name, i, msg
                ))
            })?;
        }
        Ok(())
    }
}

impl AptPin {
    fn validate(&self) -> Result<(), String> {
        if self.packages.is_empty() {
            return Err("packages must not be empty".to_string());
        }
        // `Package` separates its values by whitespace, as deb822 fields do.
        if let Some(value) = self
            .packages
            .iter()
            .find(|v| v.is_empty() || v.chars().any(|c| c.is_whitespace() || c.is_control()))
        {
            return Err(format!("packages entry {:?} is empty or contains whitespace", value));
        }
        // A newline would end the field, and the rest of the value would be read as another
        // field or as the next stanza.
        for (field, value) in [
            ("pin", Some(&self.pin)),
            ("explanation", self.explanation.as_ref()),
        ] {
            if let Some(value) = value
                && value.chars().any(char::is_control)
            {
                return Err(format!("{} {:?} contains a control character", field, value));
            }
        }
        match self.pin.split_once(' ') {
            Some(("release" | "origin" | "version", rest)) if !rest.trim().is_empty() => {}
            _ => {
                return Err(format!(
                    "pin {:?} must be 'release <filter>', 'origin <host>' or 'version <version>'",
                    self.pin
                ));
            }
        }
        if self.priority == 0 {
            return Err("priority must not be 0, which apt ignores the pin for".to_string());
        }
        Ok(())
    }
}

impl AptKeyring {
    /// Where this keyring is written, which depends on its encoding.
    pub(crate) fn path(&self, format: KeyFormat) -> RelPath {
        RelPath::parse(&format!("{}/{}.{}", KEYRINGS_DIR, self.name, format.extension()))
            .expect("a validated keyring name forms a single path component")
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        validate_name("keyring", &self.name)?;
        self.validate_source().map_err(|e| match e {
            RsdebstrapError::Validation(msg) => {
                RsdebstrapError::Validation(format!("apt keyring '{}': {}", self.name, msg))
            }
            other => other,
        })
    }

    fn validate_source(&self) -> Result<(), RsdebstrapError> {
        if let Some(sha256) = &self.sha256
            && !(sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(RsdebstrapError::Validation(format!(
                "sha256 '{}' is not 64 hex digits",
                sha256
            )));
        }
        match &self.source {
            AptKeySource::Path(path) => {
                crate::phase::validate_no_parent_dirs(path, "apt keyring")?;
                crate::phase::validate_host_file_exists(path, "apt keyring")
            }
            AptKeySource::Content(content) => {
                if content.len() as u64 > MAX_KEY_SIZE {
                    return Err(RsdebstrapError::Validation(format!(
                        "inline key is {} bytes, refusing a key over {} bytes",
                        content.len(),
                        MAX_KEY_SIZE
                    )));
                }
                // Inline content is text, and a binary keyring does not survive YAML, so
                // only the armored form is accepted here.
                match KeyFormat::detect(content.as_bytes())? {
                    KeyFormat::Armored => self.check_sha256(content.as_bytes()),
                    KeyFormat::Binary => Err(RsdebstrapError::Validation(
                        "inline content must be ASCII-armored".to_string(),
                    )),
                }
            }
            AptKeySource::Url(url) => {
                let parsed = url::Url::parse(url).map_err(|e| {
                    RsdebstrapError::Validation(format!("url '{}' is not a valid URL: {}", url, e))
                })?;
                // The key is a trust anchor for every package the repository serves, so
                // it is not fetched over a channel anyone on the path can rewrite.
                if parsed.scheme() != "https" {
                    return Err(RsdebstrapError::Validation(format!(
                        "url '{}' must use https",
                        url
                    )));
                }
                Ok(())
            }
        }
    }

    /// Checks `bytes` against `sha256`, if one was given.
    pub(crate) fn check_sha256(&self, bytes: &[u8]) -> Result<(), RsdebstrapError> {
        use sha2::{Digest, Sha256};

        let Some(expected) = &self.sha256 else {
            return Ok(());
        };
        let actual: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(RsdebstrapError::Validation(format!(
                "sha256 mismatch: expected {}, got {}",
                expected, actual
            )));
        }
        Ok(())
    }
}

impl PhaseItem for AptTask {
    fn name(&self) -> Cow<'_, str> {
        let keyrings: Vec<&str> = self.keyrings.iter().map(|k| k.name.as_str()).collect();
        let repos: Vec<&str> = self.repositories.iter().map(|r| r.name.as_str()).collect();
        let prefs: Vec<&str> = self.preferences.iter().map(|p| p.name.as_str()).collect();
        Cow::Owned(format!(
            "apt:keyrings[{}],repositories[{}],preferences[{}]",
            keyrings.join(","),
            repos.join(","),
            prefs.join(",")
        ))
    }

    fn validate(&self) -> Result<(), RsdebstrapError> {
        AptTask::validate(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARMORED: &str =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBF\n-----END PGP PUBLIC KEY BLOCK-----\n";

    fn repo(name: &str) -> AptRepository {
        AptRepository {
            name: name.to_string(),
            types: default_types(),
            uris: vec!["https://example.com/debian".to_string()],
            suites: vec!["trixie".to_string()],
            components: vec!["main".to_string()],
            architectures: vec![],
            signed_by: None,
            keep: false,
        }
    }

    fn keyring(name: &str, source: AptKeySource) -> AptKeyring {
        AptKeyring {
            name: name.to_string(),
            source,
            sha256: None,
            keep: false,
        }
    }

    fn inline(name: &str) -> AptKeyring {
        keyring(name, AptKeySource::Content(ARMORED.to_string()))
    }

    fn task(keyrings: Vec<AptKeyring>, repositories: Vec<AptRepository>) -> AptTask {
        AptTask {
            keyrings,
            repositories,
            preferences: vec![],
        }
    }

    fn pin(pin: &str, priority: i32) -> AptPin {
        AptPin {
            packages: vec!["*".to_string()],
            pin: pin.to_string(),
            priority,
            explanation: None,
        }
    }

    fn preference(name: &str, pins: Vec<AptPin>) -> AptPreference {
        AptPreference {
            name: name.to_string(),
            pins,
            keep: false,
        }
    }

    fn with_preferences(preferences: Vec<AptPreference>) -> AptTask {
        AptTask {
            preferences,
            ..task(vec![], vec![])
        }
    }

    fn validation_message(result: Result<(), RsdebstrapError>) -> String {
        match result.unwrap_err() {
            RsdebstrapError::Validation(msg) => msg,
            other => panic!("expected a validation error, got {:?}", other),
        }
    }

    #[test]
    fn deserialize_full_task() {
        // editorconfig-checker-disable
        let yaml = r#"
keyrings:
  - name: docker
    url: https://download.docker.com/linux/debian/gpg
    sha256: 1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570
    keep: true
repositories:
  - name: docker
    types: [deb, deb-src]
    uris: [https://download.docker.com/linux/debian]
    suites: [trixie]
    components: [stable]
    architectures: [amd64]
    signed_by: docker
    keep: true
"#;
        // editorconfig-checker-enable
        let task: AptTask = yaml_serde::from_str(yaml).unwrap();
        let keyring = &task.keyrings[0];
        assert!(matches!(&keyring.source, AptKeySource::Url(u) if u.ends_with("/gpg")));
        assert!(keyring.sha256.is_some());
        assert!(keyring.keep);
        let repo = &task.repositories[0];
        assert_eq!(repo.types, vec![AptSourceType::Deb, AptSourceType::DebSrc]);
        assert_eq!(repo.signed_by.as_deref(), Some("docker"));
        assert!(repo.keep);
    }

    #[test]
    fn deserialize_defaults() {
        let yaml = "repositories:\n  - name: x\n    uris: [https://e.com]\n    suites: [s]\n    \
            components: [main]\n";
        let task: AptTask = yaml_serde::from_str(yaml).unwrap();
        assert!(task.keyrings.is_empty());
        let repo = &task.repositories[0];
        assert_eq!(repo.types, vec![AptSourceType::Deb]);
        assert!(!repo.keep);
        assert!(repo.signed_by.is_none());
    }

    #[test]
    fn deserialize_rejects_missing_uris() {
        let yaml = "repositories:\n  - name: x\n    suites: [s]\n";
        assert!(yaml_serde::from_str::<AptTask>(yaml).is_err());
    }

    #[test]
    fn deserialize_keyring_rejects_two_sources() {
        let yaml = "name: k\npath: ./k.asc\nurl: https://e.com/k\n";
        let err = yaml_serde::from_str::<AptKeyring>(yaml).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "{}", err);
    }

    #[test]
    fn deserialize_keyring_rejects_no_source() {
        let yaml = "name: k\nsha256: abc\n";
        let err = yaml_serde::from_str::<AptKeyring>(yaml).unwrap_err();
        assert!(err.to_string().contains("must be specified"), "{}", err);
    }

    #[test]
    fn deserialize_rejects_unknown_type() {
        let yaml = "repositories:\n  - name: x\n    types: [rpm]\n    uris: [https://e.com]\n    \
            suites: [s]\n";
        assert!(yaml_serde::from_str::<AptTask>(yaml).is_err());
    }

    #[test]
    fn keyring_roundtrips_through_yaml() {
        let mut k = inline("k");
        k.keep = true;
        let yaml = yaml_serde::to_string(&k).unwrap();
        assert_eq!(yaml_serde::from_str::<AptKeyring>(&yaml).unwrap(), k);
    }

    #[test]
    fn render_sources_full() {
        let mut r = repo("docker");
        r.types = vec![AptSourceType::Deb, AptSourceType::DebSrc];
        r.uris.push("https://mirror.example.com/debian".to_string());
        r.architectures = vec!["amd64".to_string(), "arm64".to_string()];
        let key = inline("docker").path(KeyFormat::Armored);
        assert_eq!(
            r.render_sources(Some(&key)),
            "# Generated by rsdebstrap\n\
            Types: deb deb-src\n\
            URIs: https://example.com/debian https://mirror.example.com/debian\n\
            Suites: trixie\n\
            Components: main\n\
            Architectures: amd64 arm64\n\
            Signed-By: /etc/apt/keyrings/docker.asc\n"
        );
    }

    #[test]
    fn render_sources_omits_absent_optional_fields() {
        let mut r = repo("flat");
        r.suites = vec!["./".to_string()];
        r.components = vec![];
        let rendered = r.render_sources(None);
        assert!(!rendered.contains("Components"));
        assert!(!rendered.contains("Architectures"));
        assert!(!rendered.contains("Signed-By"));
    }

    #[test]
    fn paths_follow_name_and_key_format() {
        assert_eq!(
            repo("docker").sources_path().to_string(),
            "/etc/apt/sources.list.d/docker.sources"
        );
        assert_eq!(
            inline("docker").path(KeyFormat::Binary).to_string(),
            "/etc/apt/keyrings/docker.gpg"
        );
    }

    #[test]
    fn detect_key_formats() {
        assert_eq!(KeyFormat::detect(ARMORED.as_bytes()).unwrap(), KeyFormat::Armored);
        assert_eq!(
            KeyFormat::detect(b"\n  -----BEGIN PGP PUBLIC KEY BLOCK-----").unwrap(),
            KeyFormat::Armored
        );
        assert_eq!(KeyFormat::detect(&[0x99, 0x01, 0x0d]).unwrap(), KeyFormat::Binary);
        assert_eq!(KeyFormat::detect(&[0xC6, 0x01]).unwrap(), KeyFormat::Binary);
    }

    #[test]
    fn detect_refuses_what_is_not_a_public_key() {
        assert!(KeyFormat::detect(b"<!doctype html>").is_err());
        assert!(KeyFormat::detect(b"-----BEGIN PGP PRIVATE KEY BLOCK-----").is_err());
        // Tag 5, a Secret-Key packet, in both packet formats.
        assert!(KeyFormat::detect(&[0xC5, 0x01]).is_err());
        assert!(KeyFormat::detect(&[0x95, 0x01]).is_err());
        assert!(KeyFormat::detect(b"").is_err());
    }

    #[test]
    fn validate_accepts_a_repository_signed_by_a_keyring_of_the_same_name() {
        let mut r = repo("docker");
        r.signed_by = Some("docker".to_string());
        assert!(task(vec![inline("docker")], vec![r]).validate().is_ok());
    }

    #[test]
    fn validate_accepts_keyrings_alone() {
        assert!(task(vec![inline("k")], vec![]).validate().is_ok());
    }

    #[test]
    fn validate_rejects_an_empty_task() {
        let msg = validation_message(task(vec![], vec![]).validate());
        assert!(msg.contains("at least one"), "{}", msg);
    }

    #[test]
    fn validate_rejects_duplicate_names() {
        let msg = validation_message(task(vec![], vec![repo("a"), repo("a")]).validate());
        assert!(msg.contains("repository name 'a' is used more than once"), "{}", msg);
        let msg = validation_message(task(vec![inline("k"), inline("k")], vec![]).validate());
        assert!(msg.contains("keyring name 'k' is used more than once"), "{}", msg);
    }

    #[test]
    fn validate_rejects_names_apt_would_ignore_or_that_escape_the_directory() {
        for name in ["", ".hidden", "a/b", "..", "a b", "docker.list~"] {
            let msg = validation_message(task(vec![], vec![repo(name)]).validate());
            assert!(msg.contains("must be non-empty"), "{:?}: {}", name, msg);
            let msg = validation_message(task(vec![inline(name)], vec![]).validate());
            assert!(msg.contains("must be non-empty"), "{:?}: {}", name, msg);
        }
    }

    #[test]
    fn validate_rejects_signed_by_naming_no_keyring() {
        let mut r = repo("x");
        r.signed_by = Some("missing".to_string());
        let msg = validation_message(task(vec![inline("other")], vec![r]).validate());
        assert!(msg.contains("names no entry in keyrings"), "{}", msg);
    }

    #[test]
    fn validate_rejects_a_kept_repository_on_a_temporary_keyring() {
        let mut r = repo("x");
        r.signed_by = Some("k".to_string());
        r.keep = true;
        let msg = validation_message(task(vec![inline("k")], vec![r]).validate());
        assert!(msg.contains("must be kept too"), "{}", msg);
    }

    #[test]
    fn validate_accepts_a_temporary_repository_on_a_kept_keyring() {
        let mut r = repo("x");
        r.signed_by = Some("k".to_string());
        let mut k = inline("k");
        k.keep = true;
        assert!(task(vec![k], vec![r]).validate().is_ok());
    }

    #[test]
    fn validate_rejects_whitespace_inside_a_value() {
        let mut r = repo("x");
        r.suites = vec!["trixie main".to_string()];
        let msg = validation_message(task(vec![], vec![r]).validate());
        assert!(msg.contains("whitespace"), "{}", msg);
    }

    #[test]
    fn validate_rejects_a_newline_that_would_inject_a_field() {
        let mut r = repo("x");
        r.components = vec!["main\nTrusted: yes".to_string()];
        assert!(task(vec![], vec![r]).validate().is_err());
    }

    #[test]
    fn validate_rejects_an_invalid_uri() {
        let mut r = repo("x");
        r.uris = vec!["example.com/debian".to_string()];
        let msg = validation_message(task(vec![], vec![r]).validate());
        assert!(msg.contains("not a valid URI"), "{}", msg);
    }

    #[test]
    fn validate_requires_components_for_a_distribution_suite() {
        let mut r = repo("x");
        r.components = vec![];
        let msg = validation_message(task(vec![], vec![r]).validate());
        assert!(msg.contains("components must not be empty"), "{}", msg);
    }

    #[test]
    fn validate_rejects_components_on_an_exact_path_suite() {
        let mut r = repo("x");
        r.suites = vec!["./".to_string()];
        let msg = validation_message(task(vec![], vec![r]).validate());
        assert!(msg.contains("takes no components"), "{}", msg);
    }

    #[test]
    fn validate_rejects_mixed_exact_and_distribution_suites() {
        let mut r = repo("x");
        r.suites = vec!["./".to_string(), "trixie".to_string()];
        r.components = vec![];
        let msg = validation_message(task(vec![], vec![r]).validate());
        assert!(msg.contains("all exact paths"), "{}", msg);
    }

    #[test]
    fn validate_rejects_a_plain_http_key_url() {
        let k = keyring("k", AptKeySource::Url("http://example.com/key.asc".to_string()));
        let msg = validation_message(task(vec![k], vec![]).validate());
        assert!(msg.contains("must use https"), "{}", msg);
    }

    #[test]
    fn validate_rejects_inline_content_that_is_not_an_armored_public_key() {
        let k = keyring(
            "k",
            AptKeySource::Content("-----BEGIN PGP PRIVATE KEY BLOCK-----".to_string()),
        );
        let msg = validation_message(task(vec![k], vec![]).validate());
        assert!(msg.contains("not an OpenPGP public key"), "{}", msg);
    }

    #[test]
    fn validate_checks_the_sha256_of_inline_content() {
        let mut k = inline("k");
        k.sha256 = Some("0".repeat(64));
        let msg = validation_message(task(vec![k], vec![]).validate());
        assert!(msg.contains("sha256 mismatch"), "{}", msg);
    }

    #[test]
    fn validate_rejects_a_malformed_sha256() {
        let mut k = keyring("k", AptKeySource::Url("https://example.com/key".to_string()));
        k.sha256 = Some("abc".to_string());
        let msg = validation_message(task(vec![k], vec![]).validate());
        assert!(msg.contains("64 hex digits"), "{}", msg);
    }

    #[test]
    fn check_sha256_accepts_the_matching_digest_in_either_case() {
        // SHA-256 of the empty input.
        let mut k = keyring("k", AptKeySource::Url("https://example.com/key".to_string()));
        k.sha256 =
            Some("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855".to_string());
        assert!(k.check_sha256(b"").is_ok());
    }

    #[test]
    fn resolve_paths_joins_relative_keyring_paths_only() {
        let mut t = task(
            vec![
                keyring("a", AptKeySource::Path("keys/a.asc".into())),
                keyring("b", AptKeySource::Path("/abs/b.asc".into())),
            ],
            vec![],
        );
        t.resolve_paths(Utf8Path::new("/profiles"));
        let paths: Vec<_> = t
            .keyrings
            .iter()
            .map(|k| match &k.source {
                AptKeySource::Path(p) => p.to_string(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(paths, ["/profiles/keys/a.asc", "/abs/b.asc"]);
    }

    #[test]
    fn deserialize_preferences() {
        // editorconfig-checker-disable
        let yaml = r#"
preferences:
  - name: backports
    keep: true
    pins:
      - packages: ["*"]
        pin: release n=trixie-backports
        priority: 100
      - packages: [linux-image-amd64, "src:linux"]
        pin: release n=trixie-backports
        priority: 990
        explanation: newer kernel
"#;
        // editorconfig-checker-enable
        let task: AptTask = yaml_serde::from_str(yaml).unwrap();
        let p = &task.preferences[0];
        assert!(p.keep);
        assert_eq!(p.pins.len(), 2);
        assert_eq!(p.pins[1].packages, ["linux-image-amd64", "src:linux"]);
        assert_eq!(p.pins[1].priority, 990);
        assert_eq!(p.pins[1].explanation.as_deref(), Some("newer kernel"));
        assert!(task.validate().is_ok());
    }

    #[test]
    fn deserialize_pin_rejects_a_missing_priority() {
        let yaml = "packages: ['*']\npin: origin example.com\n";
        assert!(yaml_serde::from_str::<AptPin>(yaml).is_err());
    }

    #[test]
    fn render_preferences_writes_one_stanza_per_pin() {
        let mut second = pin("origin \"download.docker.com\"", -10);
        second.packages = vec!["docker-ce".to_string(), "containerd.io".to_string()];
        second.explanation = Some("not from docker".to_string());
        let p = preference("mixed", vec![pin("release n=trixie-backports", 500), second]);
        assert_eq!(
            p.render(),
            "# Generated by rsdebstrap\n\
            Package: *\n\
            Pin: release n=trixie-backports\n\
            Pin-Priority: 500\n\
            \n\
            Explanation: not from docker\n\
            Package: docker-ce containerd.io\n\
            Pin: origin \"download.docker.com\"\n\
            Pin-Priority: -10\n"
        );
    }

    #[test]
    fn preferences_path_uses_the_pref_extension() {
        // Without `.pref`, apt would take `.backports` as an extension and skip the file.
        assert_eq!(
            preference("trixie.backports", vec![])
                .preferences_path()
                .to_string(),
            "/etc/apt/preferences.d/trixie.backports.pref"
        );
    }

    #[test]
    fn validate_accepts_preferences_alone() {
        let t = with_preferences(vec![preference("p", vec![pin("version 1.*", 1001)])]);
        assert!(t.validate().is_ok());
    }

    #[test]
    fn validate_rejects_duplicate_preference_names() {
        let p = preference("p", vec![pin("version 1.*", 1001)]);
        let msg = validation_message(with_preferences(vec![p.clone(), p]).validate());
        assert!(msg.contains("preference name 'p' is used more than once"), "{}", msg);
    }

    #[test]
    fn validate_rejects_a_preference_name_apt_would_ignore() {
        let t = with_preferences(vec![preference("a/b", vec![pin("version 1.*", 1)])]);
        let msg = validation_message(t.validate());
        assert!(msg.contains("must be non-empty"), "{}", msg);
    }

    #[test]
    fn validate_rejects_a_preference_without_pins() {
        let msg = validation_message(with_preferences(vec![preference("p", vec![])]).validate());
        assert!(msg.contains("pins must not be empty"), "{}", msg);
    }

    #[test]
    fn validate_rejects_malformed_pins() {
        let mut no_packages = pin("version 1.*", 1);
        no_packages.packages = vec![];
        let mut spaced_package = pin("version 1.*", 1);
        spaced_package.packages = vec!["a b".to_string()];
        let mut injected_explanation = pin("version 1.*", 1);
        injected_explanation.explanation = Some("x\nPin-Priority: 1001".to_string());
        for (bad, expected) in [
            (no_packages, "packages must not be empty"),
            (spaced_package, "contains whitespace"),
            (pin("release a=x\nPin-Priority: 1001", 1), "control character"),
            (injected_explanation, "control character"),
            (pin("suite trixie", 1), "must be 'release"),
            (pin("release", 1), "must be 'release"),
            (pin("release ", 1), "must be 'release"),
            (pin("version 1.*", 0), "must not be 0"),
        ] {
            let t = with_preferences(vec![preference("p", vec![bad])]);
            let msg = validation_message(t.validate());
            assert!(msg.contains("apt preference 'p': pins[0]"), "{}", msg);
            assert!(msg.contains(expected), "expected {:?} in {}", expected, msg);
        }
    }
}
