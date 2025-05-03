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
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub variant: String,
    #[serde(default)]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub components: Vec<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub aptopt: Vec<String>,
    #[serde(default)]
    pub setup_hook: Vec<String>,
    #[serde(default)]
    pub extract_hook: Vec<String>,
    #[serde(default)]
    pub essential_hook: Vec<String>,
    #[serde(default)]
    pub customize_hook: Vec<String>,
}

pub fn load_profile(path: &str) -> Result<Profile> {
    let file = File::open(path).with_context(|| format!("failed to load file: {}", path))?;
    let reader = BufReader::new(file);
    let profile: Profile = serde_yaml::from_reader(reader)
        .with_context(|| format!("failed to parse yaml: {}", path))?;
    Ok(profile)
}
