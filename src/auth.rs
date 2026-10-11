use std::path::Path;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

pub fn private_read(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).context("read private file metadata")?;
    ensure!(metadata.is_file(), "private input must be a regular file");
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "private input must have mode 0600 or stricter"
    );
    ensure!(metadata.len() <= 1024 * 1024, "private input exceeds 1 MiB");
    std::fs::read(path).context("read private input")
}

impl Credentials {
    pub fn load(path: &Path) -> Result<Self> {
        let credentials: Self = serde_json::from_slice(&private_read(path)?).map_err(|_| {
            anyhow::anyhow!("invalid credentials JSON; expected username and password")
        })?;
        ensure!(
            !credentials.username.is_empty()
                && !credentials.password.is_empty()
                && credentials.username.len() <= 255
                && credentials.password.len() <= 255
                && !credentials.username.contains(':')
                && !credentials.username.contains(['\r', '\n', '\0'])
                && !credentials.password.contains(['\r', '\n', '\0']),
            "credentials require nonempty username/password of at most 255 bytes; username cannot contain ':'"
        );
        Ok(credentials)
    }

    pub fn basic(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.username, self.password))
        )
    }

    pub fn matches(&self, username: &[u8], password: &[u8]) -> bool {
        constant_eq(self.username.as_bytes(), username)
            & constant_eq(self.password.as_bytes(), password)
    }

    pub fn accepts(&self, headers: &hyper::HeaderMap) -> bool {
        let mut values = headers.get_all("proxy-authorization").iter();
        let Some(value) = values.next().and_then(|v| v.to_str().ok()) else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        let Some((scheme, encoded)) = value.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Ok(decoded) = STANDARD.decode(encoded) else {
            return false;
        };
        let Some(colon) = decoded.iter().position(|b| *b == b':') else {
            return false;
        };
        self.matches(&decoded[..colon], &decoded[colon + 1..])
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for (index, byte) in a.iter().enumerate() {
        diff |= usize::from(byte ^ b.get(index).copied().unwrap_or(0));
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_are_private_and_duplicates_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        crate::store::atomic_write(&path, br#"{"username":"user","password":"pass"}"#).unwrap();
        let credentials = Credentials::load(&path).unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("proxy-authorization", credentials.basic().parse().unwrap());
        assert!(credentials.accepts(&headers));
        headers.append("proxy-authorization", credentials.basic().parse().unwrap());
        assert!(!credentials.accepts(&headers));
        assert!(!credentials.matches(b"user", b"pass\0"));
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Credentials::load(&path).is_err());
    }
}
