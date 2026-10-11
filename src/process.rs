use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientProcess {
    pub pid: u32,
    pub name: String,
}

struct Cached {
    process: ClientProcess,
    fd: PathBuf,
    expires: Instant,
}

#[derive(Default)]
pub struct Attributor {
    cache: Mutex<BTreeMap<u64, Cached>>,
}

fn bounded_text(path: &Path, limit: usize) -> Option<String> {
    let mut value = String::new();
    fs::File::open(path)
        .ok()?
        .take(limit as u64 + 1)
        .read_to_string(&mut value)
        .ok()?;
    (value.len() <= limit).then_some(value)
}

fn socket(value: &str) -> Option<SocketAddr> {
    let (ip, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let address = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(ip, 16).ok()?.to_ne_bytes(),
        )),
        32 => {
            let mut bytes = [0; 16];
            for (index, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                chunk.copy_from_slice(
                    &u32::from_str_radix(&ip[index * 8..index * 8 + 8], 16)
                        .ok()?
                        .to_ne_bytes(),
                );
            }
            let ip = Ipv6Addr::from(bytes);
            ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4)
        }
        _ => return None,
    };
    Some(SocketAddr::new(address, port))
}

fn normalize(address: SocketAddr) -> SocketAddr {
    if let IpAddr::V6(ip) = address.ip()
        && let Some(ip) = ip.to_ipv4_mapped()
    {
        return SocketAddr::new(IpAddr::V4(ip), address.port());
    }
    address
}

fn inode(root: &Path, peer: SocketAddr, local: SocketAddr, uid: u32) -> Option<u64> {
    for file in ["net/tcp", "net/tcp6"] {
        let Some(table) = bounded_text(&root.join(file), 4 * 1024 * 1024) else {
            continue;
        };
        for line in table.lines().skip(1).take(16_384) {
            let columns: Vec<_> = line.split_whitespace().take(10).collect();
            if columns.len() == 10
                && columns[3] == "01"
                && socket(columns[1]) == Some(peer)
                && socket(columns[2]) == Some(local)
                && columns[7].parse::<u32>().ok() == Some(uid)
            {
                return columns[9].parse().ok();
            }
        }
    }
    None
}

fn owns(fd: &Path, inode: u64) -> bool {
    fs::read_link(fd).is_ok_and(|link| link.as_os_str() == format!("socket:[{inode}]").as_str())
}

impl Attributor {
    pub fn lookup(&self, peer: SocketAddr, local: SocketAddr) -> Option<ClientProcess> {
        self.lookup_at(
            Path::new("/proc"),
            peer,
            local,
            fs::metadata("/proc/self").ok()?.uid(),
        )
    }

    fn lookup_at(
        &self,
        root: &Path,
        peer: SocketAddr,
        local: SocketAddr,
        uid: u32,
    ) -> Option<ClientProcess> {
        let (peer, local) = (normalize(peer), normalize(local));
        if !peer.ip().is_loopback() {
            return None;
        }
        // Run one scan at a time with resource limits. Failed scans give no process ID.
        let mut cache = self.cache.lock().unwrap();
        let inode = inode(root, peer, local, uid)?;
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires > now);
        if let Some(entry) = cache.get(&inode)
            && owns(&entry.fd, inode)
            && fs::metadata(entry.fd.parent()?.parent()?).ok()?.uid() == uid
        {
            return Some(entry.process.clone());
        }
        let mut descriptors = 0;
        for process in fs::read_dir(root).ok()?.take(4096).flatten() {
            let Some(pid) = process
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let path = process.path();
            if !fs::metadata(&path).is_ok_and(|metadata| metadata.uid() == uid) {
                continue;
            }
            let Ok(fds) = fs::read_dir(path.join("fd")) else {
                continue;
            };
            for fd in fds.take(1024).flatten() {
                descriptors += 1;
                if descriptors > 16_384 {
                    return None;
                }
                if !owns(&fd.path(), inode) {
                    continue;
                }
                let name = bounded_text(&path.join("comm"), 256)?
                    .trim()
                    .chars()
                    .filter(|character| !character.is_control())
                    .take(64)
                    .collect::<String>();
                if name.is_empty() {
                    return None;
                }
                // Validate the live socket tuple again because the process can exit during the scan.
                if self::inode(root, peer, local, uid) != Some(inode) || !owns(&fd.path(), inode) {
                    return None;
                }
                let process = ClientProcess { pid, name };
                if cache.len() >= 128 {
                    cache.clear();
                }
                cache.insert(
                    inode,
                    Cached {
                        process: process.clone(),
                        fd: fd.path(),
                        expires: now + Duration::from_secs(2),
                    },
                );
                return Some(process);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_ipv6_same_user_tuple_and_live_cache_verification() {
        assert_eq!(
            socket("0100007F:1F90"),
            Some("127.0.0.1:8080".parse().unwrap())
        );
        assert_eq!(
            socket("00000000000000000000000001000000:1F90"),
            Some("[::1]:8080".parse().unwrap())
        );
        assert_eq!(
            socket("0000000000000000FFFF00000100007F:1F90"),
            Some("127.0.0.1:8080".parse().unwrap())
        );
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("net")).unwrap();
        fs::create_dir_all(root.path().join("42/fd")).unwrap();
        let uid = fs::metadata(root.path()).unwrap().uid();
        fs::write(
            root.path().join("net/tcp"),
            format!("header\n0: 0100007F:C350 0100007F:1F90 01 0:0 0:0 0 {uid} 0 12345\n"),
        )
        .unwrap();
        fs::write(root.path().join("42/comm"), "test-client\n").unwrap();
        std::os::unix::fs::symlink("socket:[12345]", root.path().join("42/fd/7")).unwrap();
        let attribution = Attributor::default();
        let peer = "127.0.0.1:50000".parse().unwrap();
        let local = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(
            attribution.lookup_at(root.path(), peer, local, uid),
            Some(ClientProcess {
                pid: 42,
                name: "test-client".into()
            })
        );
        assert_eq!(
            attribution.lookup_at(root.path(), peer, local, uid + 1),
            None
        );
        assert_eq!(
            attribution.lookup_at(root.path(), "192.0.2.1:50000".parse().unwrap(), local, uid),
            None
        );
        fs::remove_file(root.path().join("42/fd/7")).unwrap();
        assert_eq!(attribution.lookup_at(root.path(), peer, local, uid), None);
    }
}
