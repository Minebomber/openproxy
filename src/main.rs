mod api;
mod auth;
mod breakpoints;
mod ca;
mod compare;
mod config;
mod connector;
mod linux;
mod mirror;
mod network;
mod process;
mod protocols;
mod proxy;
mod rules;
mod simulation;
mod store;
mod validation;
mod websocket;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(version, about = "Open-source HTTP/HTTPS debugging proxy for Linux")]
struct Options {
    #[command(subcommand)]
    command: Option<Commands>,
    /// Listen for HTTP proxy requests and device certificate setup
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// Listen for SOCKS5 TCP connections and HTTP/HTTPS inspection
    #[arg(long)]
    socks: Option<SocketAddr>,
    /// Start a reverse HTTP proxy: LISTEN_ADDR=HTTP(S)_URL. Use the option for each listener
    #[arg(long)]
    reverse: Vec<String>,
    /// Forward TCP: LISTEN_ADDR=HOST:PORT. Use the option for each listener
    #[arg(long)]
    forward: Vec<String>,
    /// Set the local inspector address. Use a loopback address
    #[arg(long, default_value = "127.0.0.1:8081")]
    ui: SocketAddr,
    /// Give a device IP or subnet access. Loopback clients always have access
    #[arg(long)]
    allow_client: Vec<IpNet>,
    /// Set the private directory for the CA, settings, and saved session
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,
    /// Load JSON settings to replace saved settings at startup
    #[arg(long)]
    config: Option<PathBuf>,
    /// Add upstream CA certificates in PEM format. TLS verification stays enabled
    #[arg(long)]
    upstream_ca: Option<PathBuf>,
    /// Set an upstream HTTP/HTTPS CONNECT or SOCKS5 proxy URL. Do not include credentials in the URL
    #[arg(long)]
    upstream_proxy: Option<String>,
    /// Load the upstream proxy username and password from a private JSON file
    #[arg(long)]
    upstream_auth: Option<PathBuf>,
    /// Use a private JSON username/password file for mandatory HTTP Basic/SOCKS5 authentication
    #[arg(long)]
    proxy_auth: Option<PathBuf>,
    /// Use a PEM certificate chain for upstream mutual TLS
    #[arg(long, requires = "client_key")]
    client_cert: Option<PathBuf>,
    /// Use a private PEM key for upstream mutual TLS
    #[arg(long, requires = "client_cert")]
    client_key: Option<PathBuf>,
    /// Send the client certificate only to this upstream hostname. Use the option for each host
    #[arg(long, requires = "client_cert")]
    client_cert_host: Vec<String>,
    /// Make a new CA. Save a private backup of the previous identity
    #[arg(long, conflicts_with = "import_ca_cert")]
    rotate_ca: bool,
    /// Import a PEM CA certificate. Save a private backup of the previous identity
    #[arg(long, requires = "import_ca_key")]
    import_ca_cert: Option<PathBuf>,
    /// Use the private PEM key that matches the imported CA
    #[arg(long, requires = "import_ca_cert")]
    import_ca_key: Option<PathBuf>,
    /// Prepare or replace the CA. Export its certificates. Exit without listeners
    #[arg(long)]
    ca_only: bool,
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u16).range(1..=4096))]
    max_connections: u16,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Set or restore the GNOME desktop proxy
    #[command(subcommand)]
    SystemProxy(linux::ProxyCommand),
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse();
    if let Some(Commands::SystemProxy(command)) = options.command {
        return linux::run(command, &options.data_dir);
    }
    ensure!(
        options.ui.ip().is_loopback(),
        "management GUI must listen on loopback"
    );
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    store::private_dir(&options.data_dir)?;
    use std::os::unix::fs::OpenOptionsExt;
    let data_lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(options.data_dir.join(".instance.lock"))?;
    data_lock
        .try_lock()
        .context("another OpenProxy instance is using this data directory")?;
    let outbound = connector::Options::load(&options)?;
    if options.rotate_ca || options.import_ca_cert.is_some() {
        let backup = ca::Authority::replace(
            &options.data_dir,
            options.import_ca_cert.as_deref(),
            options.import_ca_key.as_deref(),
        )?;
        if let Some(path) = backup {
            println!("Previous CA private backup: {}", path.display());
        }
    }
    let ca = ca::Authority::load(&options.data_dir)?;
    if options.ca_only {
        println!("CA PEM: {}", options.data_dir.join("ca.pem").display());
        return Ok(());
    }
    let config_path = options
        .config
        .as_ref()
        .unwrap_or(&options.data_dir.join("settings.json"))
        .to_owned();
    let settings = if config_path.exists() {
        serde_json::from_slice(&std::fs::read(&config_path)?).context("invalid settings JSON")?
    } else {
        config::Settings::default()
    };
    config::validate(&settings)?;
    ensure!(
        options.reverse.len() + options.forward.len() <= 32,
        "at most 32 reverse/TCP listeners"
    );
    let mut specs = Vec::new();
    for spec in &options.reverse {
        specs.push(network::reverse(spec)?);
    }
    for spec in &options.forward {
        specs.push(network::forwarding(spec)?);
    }
    let proxy_listener = TcpListener::bind(options.listen)
        .await
        .context("bind proxy listener")?;
    let ui_listener = TcpListener::bind(options.ui)
        .await
        .context("bind management listener")?;
    let socks_listener = if let Some(addr) = options.socks {
        Some(
            TcpListener::bind(addr)
                .await
                .context("bind SOCKS listener")?,
        )
    } else {
        None
    };
    let socks_addr = socks_listener
        .as_ref()
        .map(TcpListener::local_addr)
        .transpose()?;
    let mut listeners = vec![(proxy_listener, network::Mode::Http)];
    if let Some(listener) = socks_listener {
        listeners.push((listener, network::Mode::Socks));
    }
    for (addr, mode) in specs {
        listeners.push((
            TcpListener::bind(addr)
                .await
                .context("bind reverse/TCP listener")?,
            mode,
        ));
    }
    let state = Arc::new(proxy::App::new(
        ca,
        settings,
        options.data_dir,
        outbound,
        listeners[0].0.local_addr()?,
        ui_listener.local_addr()?,
        socks_addr,
    )?);
    println!("OpenProxy {}", env!("CARGO_PKG_VERSION"));
    println!("Proxy: {}", state.proxy_addr);
    println!("Inspector: http://{}/#{}", state.ui_addr, state.token);
    println!("Public CA: http://openproxy.local/ca.cer (through the proxy)");
    println!("CA PEM: {}", state.data_dir.join("ca.pem").display());
    if let Some(addr) = socks_addr {
        println!("SOCKS5: {addr}");
    }
    for (listener, mode) in &listeners {
        match mode {
            network::Mode::Reverse(uri) => println!("Reverse: {} -> {uri}", listener.local_addr()?),
            network::Mode::Tcp(target) => println!("TCP: {} -> {target}", listener.local_addr()?),
            _ => {}
        }
    }
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    let mut proxy_tasks = tokio::task::JoinSet::new();
    for (listener, mode) in listeners {
        proxy_tasks.spawn(proxy::listen(
            listener,
            state.clone(),
            options.allow_client.clone(),
            options.max_connections as usize,
            mode,
            receiver.clone(),
        ));
    }
    let api_state = state.clone();
    let mut api_shutdown = receiver.clone();
    let mut api_task = tokio::spawn(async move {
        axum::serve(ui_listener, api::router(api_state))
            .with_graceful_shutdown(async move {
                let _ = api_shutdown.changed().await;
            })
            .await
    });
    let save_state = state.clone();
    let mut save_shutdown = receiver;
    let saver = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(error) = save_state.save_session().await {
                        eprintln!("Autosave failed: {error:#}");
                    }
                }
                _ = save_shutdown.changed() => break,
            }
        }
    });
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        signal = tokio::signal::ctrl_c() => { signal?; }
        _ = terminate.recv() => {},
        result = proxy_tasks.join_next() => { result.unwrap()??; anyhow::bail!("proxy listener stopped"); }
        result = &mut api_task => { result??; anyhow::bail!("management listener stopped"); }
    }
    shutdown.send(true)?;
    state.breakpoints.close();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let proxy_end = async { while proxy_tasks.join_next().await.is_some() {} };
        let _ = tokio::join!(proxy_end, api_task);
    })
    .await;
    saver.await?;
    state.save_session().await?;
    Ok(())
}
