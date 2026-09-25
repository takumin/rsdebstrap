//! Downloads over https, shared by everything a profile can name by `url`.

use std::io::Write;
use std::time::Duration;

use anyhow::{Context, Result};

/// An agent that only speaks https, redirects included, so a server cannot bounce a request to
/// plain http. Certificates are checked against the host's trust store rather than a bundled
/// one, so a file served behind an internal CA verifies the way the host's own tools would.
fn agent(timeout: Duration) -> ureq::Agent {
    use ureq::tls::{RootCerts, TlsConfig};

    ureq::Agent::config_builder()
        .https_only(true)
        .timeout_global(Some(timeout))
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .into()
}

/// Downloads `url` into memory, refusing a body over `limit` bytes.
pub(crate) fn get_to_vec(url: &str, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut response = agent(Duration::from_secs(60))
        .get(url)
        .call()
        .with_context(|| format!("failed to download {} from {}", label, url))?;
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .with_context(|| format!("failed to read {} from {}", label, url))
}

/// Downloads `url` into `sink`, refusing a body over `limit` bytes, and returns how many bytes
/// were written.
///
/// Streamed rather than buffered: a firmware blob or an image can be large, and the caller
/// writes it to a staging file anyway. The timeout covers the whole transfer, so it is longer
/// than [`get_to_vec`]'s, which only ever fetches a few kilobytes.
pub(crate) fn get_to_writer(
    url: &str,
    limit: u64,
    label: &str,
    sink: &mut dyn Write,
) -> Result<u64> {
    let mut response = agent(Duration::from_secs(600))
        .get(url)
        .call()
        .with_context(|| format!("failed to download {} from {}", label, url))?;
    let mut reader = response.body_mut().with_config().limit(limit).reader();
    std::io::copy(&mut reader, sink)
        .with_context(|| format!("failed to read {} from {}", label, url))
}
