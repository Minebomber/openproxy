use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use serde::{Deserialize, Serialize};

pub struct Authority {
    issuer: Issuer<'static, KeyPair>,
    pub pem: String,
    pub der: CertificateDer<'static>,
    not_after: time::OffsetDateTime,
    cache: Mutex<HashMap<String, (Arc<ServerConfig>, i64)>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    certificate: String,
    private_key: String,
}

impl Authority {
    pub fn replace(
        dir: &Path,
        certificate: Option<&Path>,
        private_key: Option<&Path>,
    ) -> Result<Option<std::path::PathBuf>> {
        let identity = match (certificate, private_key) {
            (Some(cert), Some(key)) => Identity {
                certificate: std::fs::read_to_string(cert)
                    .context("read imported CA certificate")?,
                private_key: String::from_utf8(crate::auth::private_read(key)?)
                    .context("CA key must be PEM")?,
            },
            (None, None) => Self::generate()?,
            _ => anyhow::bail!("CA import requires both certificate and private key"),
        };
        // Validate the new CA before the backup or replacement.
        Self::from_identity(&identity)?;
        let active = dir.join("ca-identity.json");
        let backup = if active.exists() {
            let backups = dir.join("ca-backups");
            crate::store::private_dir(&backups)?;
            let path = backups.join(format!(
                "{}-{}.json",
                crate::store::now_ms(),
                uuid::Uuid::new_v4()
            ));
            crate::store::atomic_write(&path, &std::fs::read(&active)?)?;
            Some(path)
        } else {
            None
        };
        crate::store::atomic_write(&active, &serde_json::to_vec(&identity)?)?;
        Ok(backup)
    }

    fn generate() -> Result<Identity> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            DnType::CommonName,
            format!("OpenProxy CA {}", &uuid::Uuid::new_v4().to_string()[..8]),
        );
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);
        let cert = params.self_signed(&key)?;
        Ok(Identity {
            certificate: cert.pem(),
            private_key: key.serialize_pem(),
        })
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("ca-identity.json");
        let identity: Identity = if path.exists() {
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
            serde_json::from_slice(&std::fs::read(&path)?)
                .context("read CA identity (will not replace a damaged CA)")?
        } else {
            let identity = Self::generate()?;
            crate::store::atomic_write(&path, &serde_json::to_vec(&identity)?)?;
            identity
        };
        let authority = Self::from_identity(&identity)?;
        crate::store::atomic_write(&dir.join("ca.pem"), identity.certificate.as_bytes())?;
        crate::store::atomic_write(&dir.join("ca.cer"), authority.der.as_ref())?;
        Ok(authority)
    }

    fn from_identity(identity: &Identity) -> Result<Self> {
        let key = KeyPair::from_pem(&identity.private_key).context("invalid CA private key")?;
        let certs = rustls_pemfile::certs(&mut identity.certificate.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        anyhow::ensure!(
            certs.len() == 1,
            "CA identity must contain exactly one certificate"
        );
        let der = certs.into_iter().next().unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid CA certificate"))?;
        anyhow::ensure!(
            cert.validity().is_valid(),
            "CA certificate is expired or not yet valid"
        );
        anyhow::ensure!(
            cert.basic_constraints()?.is_some_and(|c| c.value.ca),
            "certificate is not a CA"
        );
        anyhow::ensure!(
            cert.key_usage()?
                .is_none_or(|usage| usage.value.key_cert_sign()),
            "CA certificate cannot sign certificates"
        );
        let not_after =
            time::OffsetDateTime::from_unix_timestamp(cert.validity().not_after.timestamp())?;
        // Rustls validates the saved private key against its certificate.
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![der.clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .context("CA key/certificate mismatch")?;
        let issuer = Issuer::from_ca_cert_pem(&identity.certificate, key)?;
        Ok(Self {
            issuer,
            pem: identity.certificate.clone(),
            der,
            not_after,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let mut cache = self.cache.lock().unwrap();
        let now = time::OffsetDateTime::now_utc();
        anyhow::ensure!(
            now < self.not_after,
            "inspection CA expired; import or rotate the CA"
        );
        if let Some((config, expires)) = cache.get(host)
            && *expires > now.unix_timestamp() + 3600
        {
            return Ok(config.clone());
        }
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.not_before = now - time::Duration::days(1);
        params.not_after = (now + time::Duration::days(7)).min(self.not_after);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&key, &self.issuer)?;
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone(), self.der.clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let config = Arc::new(config);
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(
            host.to_owned(),
            (config.clone(), params.not_after.unix_timestamp()),
        );
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ca_identity_stays_private_and_corruption_is_rejected() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = tempfile::tempdir().unwrap();
        Authority::load(dir.path()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(dir.path().join("ca-identity.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::write(dir.path().join("ca-identity.json"), "broken").unwrap();
        assert!(Authority::load(dir.path()).is_err());
    }

    #[test]
    fn imported_ca_validity_limits_host_certificates() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(1);
        params.not_after = now + time::Duration::minutes(30);
        let identity = |params: &CertificateParams| Identity {
            certificate: params.self_signed(&key).unwrap().pem(),
            private_key: key.serialize_pem(),
        };
        let mut authority = Authority::from_identity(&identity(&params)).unwrap();
        authority.server_config("localhost").unwrap();
        assert_eq!(
            authority.cache.lock().unwrap()["localhost"].1,
            params.not_after.unix_timestamp()
        );
        authority.not_after = now - time::Duration::minutes(1);
        assert!(authority.server_config("localhost").is_err());
        params.not_after = now - time::Duration::seconds(1);
        assert!(Authority::from_identity(&identity(&params)).is_err());
        params.not_after = now + time::Duration::hours(1);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        assert!(Authority::from_identity(&identity(&params)).is_err());
    }
}
