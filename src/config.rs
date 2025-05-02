use anyhow::{Context, Ok, Result};
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;

#[derive(Debug, Deserialize)]
pub struct Profile {
    pub dir: String,
    pub mmdebstrap: Mmdebstrap,
}

#[derive(Debug, Deserialize)]
pub struct Mmdebstrap {
    pub suite: String,
    pub target: String,
    /// Specifies the mode in which mmdebstrap operates.
    /// Expected values include:
    /// "auto", "sudo", "root", "unshare", "fakeroot", "fakechroot", and "chrootless"
    /// Defaults to an empty string if not specified.
    #[serde(default)]
    pub mode: String,
    /// Choose which package set to install.
    /// Expected values include:
    /// "extract", "custom", "essential", "apt", "required", "minbase", "buildd", "important", and "standard"
    /// Defaults to an empty string if not specified.
    #[serde(default)]
    pub variant: String,
    #[serde(default)]
    pub components: Vec<String>,
    #[serde(default)]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub include: Vec<String>,
}

pub fn load_profile(path: &str) -> Result<Profile> {
    let file = File::open(path).with_context(|| format!("failed to load file: {}", path))?;
    let reader = BufReader::new(file);
    let profile: Profile = serde_yaml::from_reader(reader)
        .with_context(|| format!("failed to parse yaml: {}", path))?;
    Ok(profile)
}
