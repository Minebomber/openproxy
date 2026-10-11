use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub recording: bool,
    pub intercept_hosts: Vec<String>,
    pub bypass_hosts: Vec<String>,
    pub capture_bytes: usize,
    pub max_flows: usize,
    pub latency_ms: u64,
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
    pub aggregate_upload_bytes_per_second: u64,
    pub aggregate_download_bytes_per_second: u64,
    pub offline: bool,
    pub process_attribution: bool,
    pub failure_percent: u8,
    pub drop_upload_after_bytes: Option<u64>,
    pub drop_download_after_bytes: Option<u64>,
    pub no_cache: bool,
    pub block_cookies: bool,
    pub rules: Vec<crate::rules::Rule>,
    pub dns_overrides: std::collections::BTreeMap<String, std::net::IpAddr>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            recording: true,
            intercept_hosts: vec!["*".into()],
            bypass_hosts: vec![],
            capture_bytes: 64 * 1024,
            max_flows: 1000,
            latency_ms: 0,
            upload_bytes_per_second: 0,
            download_bytes_per_second: 0,
            aggregate_upload_bytes_per_second: 0,
            aggregate_download_bytes_per_second: 0,
            offline: false,
            process_attribution: false,
            failure_percent: 0,
            drop_upload_after_bytes: None,
            drop_download_after_bytes: None,
            no_cache: false,
            block_cookies: false,
            rules: vec![],
            dns_overrides: Default::default(),
        }
    }
}

pub fn validate(settings: &Settings) -> Result<()> {
    ensure!(
        settings.failure_percent <= 100,
        "failure_percent must be 0..100"
    );
    ensure!(
        settings.dns_overrides.len() <= 256,
        "at most 256 DNS overrides"
    );
    let mut names = std::collections::BTreeSet::new();
    for host in settings.dns_overrides.keys() {
        ensure!(
            !host.is_empty()
                && host.len() <= 253
                && host.bytes().all(|byte| (33..=126).contains(&byte))
                && !host.contains(['/', '*', '?', '@', ' ']),
            "invalid DNS override host"
        );
        ensure!(
            names.insert(host.to_ascii_lowercase()),
            "duplicate DNS override host"
        );
    }
    crate::rules::validate(&settings.rules)?;
    ensure!(
        (1..=10_000).contains(&settings.max_flows),
        "max_flows must be 1..10000"
    );
    ensure!(
        settings.capture_bytes <= 1024 * 1024,
        "capture_bytes must be at most 1 MiB"
    );
    ensure!(
        settings.max_flows.saturating_mul(settings.capture_bytes) <= 128 * 1024 * 1024,
        "max_flows * capture_bytes must be at most 128 MiB (per direction)"
    );
    ensure!(
        settings.latency_ms <= 60_000,
        "latency_ms must be at most 60000"
    );
    for patterns in [&settings.intercept_hosts, &settings.bypass_hosts] {
        ensure!(patterns.len() <= 1000, "at most 1000 host patterns");
        for pattern in patterns {
            ensure!(
                !pattern.is_empty() && pattern.len() <= 253 && pattern.is_ascii(),
                "invalid host pattern"
            );
        }
    }
    Ok(())
}

pub fn matches(pattern: &str, value: &str) -> bool {
    let (pattern, value) = (pattern.as_bytes(), value.as_bytes());
    let (mut p, mut v, mut star, mut restart) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            restart = v;
        } else if let Some(s) = star {
            restart += 1;
            v = restart;
            p = s + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

impl Settings {
    pub fn intercept(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        !self
            .bypass_hosts
            .iter()
            .any(|p| matches(&p.to_ascii_lowercase(), &host))
            && self
                .intercept_hosts
                .iter()
                .any(|p| matches(&p.to_ascii_lowercase(), &host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wildcard_and_exclusion() {
        for (p, v, yes) in [
            ("*", "", true),
            ("*.example.com", "api.example.com", true),
            ("a?c", "abc", true),
            ("a*c", "abbbc", true),
            ("a*c", "ab", false),
            ("*.example.com", "example.com.attacker", false),
        ] {
            assert_eq!(matches(p, v), yes);
        }
        let settings = Settings {
            bypass_hosts: vec!["*.example.com".into()],
            ..Default::default()
        };
        assert!(!settings.intercept("API.EXAMPLE.COM"));
        assert!(settings.intercept("other.org"));
    }
    #[test]
    fn bounds() {
        assert!(validate(&Settings::default()).is_ok());
        assert!(
            validate(&Settings {
                max_flows: 10_000,
                capture_bytes: 1024 * 1024,
                ..Default::default()
            })
            .is_err()
        );
    }
}
