//! `checksum:` pins: an algorithm and the digest the bytes must hash to.
//!
//! Written `<algorithm>:<hex digest>` in a profile, e.g. `sha256:9f86d0…`. A checksum is
//! parsed when the profile is, so a malformed one is reported with the field and line rather
//! than when the bytes it pins arrive.

use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Digest;

/// A hash algorithm a checksum may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display, strum::EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Algorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    const ALL: [Self; 4] = [Self::Md5, Self::Sha1, Self::Sha256, Self::Sha512];

    /// Length of the algorithm's digest in hex digits.
    fn hex_len(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }
}

/// Expected digest of a file's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    algorithm: Algorithm,
    // Lowercase, so equality and the mismatch message do not depend on how it was written.
    digest: String,
}

impl Checksum {
    /// Parses `<algorithm>:<hex digest>`.
    ///
    /// # Errors
    ///
    /// Returns a message describing the problem if `value` names no supported algorithm or
    /// its digest is not the algorithm's length in hex digits.
    pub fn new(value: &str) -> Result<Self, String> {
        let supported = || {
            Algorithm::ALL
                .iter()
                .map(Algorithm::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let Some((name, digest)) = value.split_once(':') else {
            return Err(format!(
                "checksum '{}' must be written <algorithm>:<hex digest> (algorithm one of {})",
                value,
                supported()
            ));
        };
        let algorithm: Algorithm = name.parse().map_err(|_| {
            format!(
                "checksum '{}' names unsupported algorithm '{}' (one of {})",
                value,
                name,
                supported()
            )
        })?;
        if !(digest.len() == algorithm.hex_len() && digest.bytes().all(|b| b.is_ascii_hexdigit())) {
            return Err(format!(
                "checksum '{}': a {} digest is {} hex digits",
                value,
                algorithm,
                algorithm.hex_len()
            ));
        }
        Ok(Self {
            algorithm,
            digest: digest.to_ascii_lowercase(),
        })
    }

    /// The checksum of `bytes` under `algorithm`.
    pub fn of(algorithm: Algorithm, bytes: &[u8]) -> Self {
        let mut state = State::new(algorithm);
        state.update(bytes);
        Self {
            algorithm,
            digest: state.finalize(),
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Checks `bytes` against the checksum.
    ///
    /// # Errors
    ///
    /// Returns a message naming both digests if they differ.
    pub fn verify(&self, bytes: &[u8]) -> Result<(), String> {
        let mut hasher = self.hasher();
        hasher.update(bytes);
        hasher.verify()
    }

    /// A hasher that is fed the bytes incrementally and checked against the checksum at the
    /// end, so a large file need not be held in memory.
    pub fn hasher(&self) -> Hasher<'_> {
        Hasher {
            expected: self,
            state: State::new(self.algorithm),
        }
    }
}

/// Incremental hash of bytes to be checked against a [`Checksum`].
pub struct Hasher<'a> {
    expected: &'a Checksum,
    state: State,
}

impl Hasher<'_> {
    pub fn update(&mut self, bytes: &[u8]) {
        self.state.update(bytes);
    }

    /// Checks what was hashed against the checksum.
    ///
    /// # Errors
    ///
    /// Returns a message naming both digests if they differ.
    pub fn verify(self) -> Result<(), String> {
        let actual = self.state.finalize();
        if actual != self.expected.digest {
            return Err(format!(
                "checksum mismatch: expected {}, got {}:{}",
                self.expected, self.expected.algorithm, actual
            ));
        }
        Ok(())
    }
}

enum State {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

impl State {
    fn new(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Md5 => Self::Md5(md5::Md5::new()),
            Algorithm::Sha1 => Self::Sha1(sha1::Sha1::new()),
            Algorithm::Sha256 => Self::Sha256(sha2::Sha256::new()),
            Algorithm::Sha512 => Self::Sha512(sha2::Sha512::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Md5(h) => h.update(bytes),
            Self::Sha1(h) => h.update(bytes),
            Self::Sha256(h) => h.update(bytes),
            Self::Sha512(h) => h.update(bytes),
        }
    }

    /// The lowercase hex digest of what was hashed.
    fn finalize(self) -> String {
        let bytes = match self {
            Self::Md5(h) => h.finalize().to_vec(),
            Self::Sha1(h) => h.finalize().to_vec(),
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),
        };
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl fmt::Display for Checksum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.digest)
    }
}

impl<'de> Deserialize<'de> for Checksum {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(&value).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Checksum {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl JsonSchema for Checksum {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "Checksum".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        let pattern = format!(
            "^({})$",
            Algorithm::ALL
                .iter()
                .map(|a| format!("{}:[0-9a-fA-F]{{{}}}", a, a.hex_len()))
                .collect::<Vec<_>>()
                .join("|")
        );
        json_schema!({ "type": "string", "pattern": pattern })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Digests of the empty input.
    const MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";
    const SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA512: &str = concat!(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    );

    #[test]
    fn verifies_each_algorithm_in_either_case() {
        for value in [
            format!("md5:{MD5}"),
            format!("sha1:{SHA1}"),
            format!("sha256:{SHA256}"),
            format!("sha512:{SHA512}"),
            format!("sha256:{}", SHA256.to_ascii_uppercase()),
        ] {
            let checksum = Checksum::new(&value).unwrap();
            assert_eq!(checksum.verify(b""), Ok(()), "{value}");
        }
    }

    #[test]
    fn a_mismatch_names_both_digests() {
        let checksum = Checksum::new(&format!("sha256:{}", "0".repeat(64))).unwrap();
        let err = checksum.verify(b"").unwrap_err();
        assert!(err.contains("checksum mismatch"), "{err}");
        assert!(err.contains(&format!("got sha256:{SHA256}")), "{err}");
    }

    #[test]
    fn rejects_malformed_values_when_parsed() {
        for (value, needle) in [
            (SHA256.to_string(), "<algorithm>:<hex digest>"),
            (format!("sha384:{}", "0".repeat(96)), "unsupported algorithm 'sha384'"),
            (format!("SHA256:{SHA256}"), "unsupported algorithm"),
            (format!("sha256:{MD5}"), "64 hex digits"),
            (format!("md5:{}", "g".repeat(32)), "32 hex digits"),
        ] {
            let err = Checksum::new(&value).unwrap_err();
            assert!(err.contains(needle), "{value}: {err}");
        }
    }

    #[test]
    fn of_computes_what_verify_accepts() {
        for algorithm in Algorithm::ALL {
            let checksum = Checksum::of(algorithm, b"firmware");
            assert_eq!(checksum.verify(b"firmware"), Ok(()), "{algorithm}");
            assert_eq!(Checksum::new(&checksum.to_string()), Ok(checksum.clone()));
        }
        assert_eq!(
            Checksum::of(Algorithm::Md5, b""),
            Checksum::new(&format!("md5:{MD5}")).unwrap()
        );
    }

    #[test]
    fn displays_as_written_but_lowercased() {
        let checksum = Checksum::new(&format!("md5:{}", MD5.to_ascii_uppercase())).unwrap();
        assert_eq!(checksum.to_string(), format!("md5:{MD5}"));
    }
}
