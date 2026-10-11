use std::{net::SocketAddr, path::Path, process::Command};

use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde::{Deserialize, Serialize};

const ROOT: &str = "org.gnome.system.proxy";
const KEYS: &[(&str, &str)] = &[
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.http", "use-authentication"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    (ROOT, "use-same-proxy"),
    (ROOT, "mode"),
];

#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    /// Save GNOME HTTP/HTTPS proxy settings. Set the proxy to OpenProxy
    Enable {
        #[arg(long, default_value = "127.0.0.1:8080")]
        address: SocketAddr,
    },
    /// Restore settings only if they match the values from OpenProxy
    Restore,
    /// Show the GNOME proxy mode and backup status
    Status,
}

trait Backend {
    fn get(&self, schema: &str, key: &str) -> Result<String>;
    fn writable(&self, schema: &str, key: &str) -> Result<bool>;
    fn set(&self, schema: &str, key: &str, value: &str) -> Result<()>;
}

struct GSettings;
impl GSettings {
    fn run(args: &[&str]) -> Result<String> {
        let output = Command::new("gsettings").args(args).output().context(
            "gsettings is unavailable; use the browser/manual proxy instructions in README.md",
        )?;
        ensure!(
            output.status.success(),
            "gsettings {} failed; check that a GNOME session and writable proxy schemas are available",
            args[0]
        );
        ensure!(
            output.stdout.len() <= 8192,
            "unexpectedly large gsettings value"
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }
}
impl Backend for GSettings {
    fn get(&self, schema: &str, key: &str) -> Result<String> {
        Self::run(&["get", schema, key])
    }
    fn writable(&self, schema: &str, key: &str) -> Result<bool> {
        Ok(Self::run(&["writable", schema, key])? == "true")
    }
    fn set(&self, schema: &str, key: &str, value: &str) -> Result<()> {
        Self::run(&["set", schema, key, value])?;
        ensure!(
            self.get(schema, key)? == value,
            "desktop proxy setting {schema}/{key} did not persist"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u8,
    entries: Vec<Entry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    schema: String,
    key: String,
    original: String,
    installed: String,
}

fn enable(backend: &impl Backend, path: &Path, address: SocketAddr) -> Result<()> {
    ensure!(
        address.ip().is_loopback() && address.port() > 0,
        "system proxy address must be loopback with a nonzero port"
    );
    ensure!(
        !path.exists(),
        "a system proxy backup already exists; restore it before enabling again"
    );
    let mut entries = Vec::new();
    for (schema, key) in KEYS {
        ensure!(
            backend.writable(schema, key)?,
            "desktop proxy setting {schema}/{key} is not writable"
        );
        let installed = match *key {
            "host" => format!("'{}'", address.ip()),
            "port" => address.port().to_string(),
            "mode" => "'manual'".to_owned(),
            _ => "false".to_owned(),
        };
        entries.push(Entry {
            schema: (*schema).into(),
            key: (*key).into(),
            original: backend.get(schema, key)?,
            installed,
        });
    }
    let snapshot = Snapshot {
        version: 1,
        entries,
    };
    // Save all initial settings before the first change so an interrupted setup can restore them.
    crate::store::atomic_write(path, &serde_json::to_vec(&snapshot)?)?;
    for entry in &snapshot.entries {
        let apply = (|| {
            ensure!(
                backend.get(&entry.schema, &entry.key)? == entry.original,
                "desktop proxy settings changed while enabling; retry after restoring"
            );
            backend.set(&entry.schema, &entry.key, &entry.installed)
        })();
        if let Err(error) = apply {
            if let Err(rollback) = restore(backend, path) {
                return Err(error.context(format!(
                    "rollback also failed ({rollback:#}); backup retained at {}",
                    path.display()
                )));
            }
            return Err(error);
        }
    }
    Ok(())
}

fn restore(backend: &impl Backend, path: &Path) -> Result<Vec<String>> {
    let bytes =
        std::fs::read(path).context("no readable system proxy backup in this data directory")?;
    ensure!(
        bytes.len() <= 64 * 1024,
        "system proxy backup exceeds 64 KiB"
    );
    let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
    ensure!(
        snapshot.version == 1 && snapshot.entries.len() == KEYS.len(),
        "invalid system proxy backup"
    );
    for (entry, (schema, key)) in snapshot.entries.iter().zip(KEYS) {
        ensure!(
            entry.schema == *schema
                && entry.key == *key
                && entry.original.len() <= 8192
                && entry.installed.len() <= 8192,
            "invalid system proxy backup entry"
        );
    }
    let mut changed = Vec::new();
    // Restore the mode first to apply initial routing before proxy addresses.
    for entry in snapshot.entries.iter().rev() {
        let current = backend.get(&entry.schema, &entry.key)?;
        if current == entry.installed {
            backend.set(&entry.schema, &entry.key, &entry.original)?;
        } else if current != entry.original {
            changed.push(format!("{}/{}", entry.schema, entry.key));
        }
    }
    std::fs::remove_file(path)?;
    Ok(changed)
}

pub fn run(command: ProxyCommand, data_dir: &Path) -> Result<()> {
    crate::store::private_dir(data_dir)?;
    use std::os::unix::fs::OpenOptionsExt;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(data_dir.join(".system-proxy.lock"))?;
    lock.try_lock()
        .context("another system proxy operation is in progress")?;
    let path = data_dir.join("system-proxy-backup.json");
    match command {
        ProxyCommand::Enable { address } => {
            enable(&GSettings, &path, address)?;
            println!(
                "GNOME HTTP/HTTPS proxy enabled at {address}; restore with the same --data-dir."
            );
        }
        ProxyCommand::Restore => {
            let changed = restore(&GSettings, &path)?;
            println!("Saved GNOME proxy settings restored.");
            for key in changed {
                println!("Kept later user change: {key}");
            }
        }
        ProxyCommand::Status => {
            println!("GNOME proxy mode: {}", GSettings.get(ROOT, "mode")?);
            println!(
                "Restore backup: {}",
                if path.exists() { "available" } else { "none" }
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::BTreeMap};

    struct Memory {
        values: RefCell<BTreeMap<(String, String), String>>,
        fail_once: RefCell<bool>,
    }
    impl Memory {
        fn new() -> Self {
            Self {
                values: RefCell::new(
                    KEYS.iter()
                        .map(|(schema, key)| {
                            (
                                ((*schema).into(), (*key).into()),
                                match *key {
                                    "host" => "'previous'",
                                    "port" => "1234",
                                    "mode" => "'auto'",
                                    _ => "true",
                                }
                                .into(),
                            )
                        })
                        .collect(),
                ),
                fail_once: RefCell::new(false),
            }
        }
    }
    impl Backend for Memory {
        fn get(&self, schema: &str, key: &str) -> Result<String> {
            Ok(self.values.borrow()[&(schema.into(), key.into())].clone())
        }
        fn writable(&self, _: &str, _: &str) -> Result<bool> {
            Ok(true)
        }
        fn set(&self, schema: &str, key: &str, value: &str) -> Result<()> {
            if key == "mode" && self.fail_once.replace(false) {
                anyhow::bail!("injected write failure");
            }
            self.values
                .borrow_mut()
                .insert((schema.into(), key.into()), value.into());
            Ok(())
        }
    }

    #[test]
    fn backup_restore_preserves_later_changes_and_rolls_back_failed_enable() {
        let backend = Memory::new();
        let original = backend.values.borrow().clone();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backup.json");
        enable(&backend, &path, "127.0.0.1:8080".parse().unwrap()).unwrap();
        assert!(enable(&backend, &path, "127.0.0.1:8080".parse().unwrap()).is_err());
        backend.set(ROOT, "mode", "'none'").unwrap();
        let changed = restore(&backend, &path).unwrap();
        assert_eq!(changed, [format!("{ROOT}/mode")]);
        assert_eq!(backend.get(ROOT, "mode").unwrap(), "'none'");
        for (key, value) in original {
            if key.1 != "mode" {
                assert_eq!(backend.values.borrow()[&key], value);
            }
        }
        *backend.fail_once.borrow_mut() = true;
        let before = backend.values.borrow().clone();
        assert!(enable(&backend, &path, "127.0.0.1:8080".parse().unwrap()).is_err());
        assert_eq!(*backend.values.borrow(), before);
        assert!(!path.exists());
        assert!(enable(&backend, &path, "0.0.0.0:8080".parse().unwrap()).is_err());
    }
}
