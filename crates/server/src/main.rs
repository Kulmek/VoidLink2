//! tunnel-server: точка входа. Логика — в библиотеке крейта (`lib.rs`).

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let mut listen = "0.0.0.0:5555".to_string();
    let mut data_dir: PathBuf = tunnel_server::default_data_dir().into();
    let mut workers = 0usize;
    let mut quiet = false;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                eprintln!(
                    "Usage: tunnel-server [listen=0.0.0.0:5555] [--data <dir>=tunnel-data] \
                     [--workers N=по числу ядер, до 8] [-q]"
                );
                return Ok(());
            }
            "--data" => {
                data_dir = args.get(i + 1).context("--data requires value")?.into();
                i += 1;
            }
            "--workers" => {
                workers = args
                    .get(i + 1)
                    .context("--workers requires value")?
                    .parse()
                    .context("--workers: число")?;
                i += 1;
            }
            "-q" | "--quiet" => quiet = true,
            other => listen = other.to_string(),
        }
        i += 1;
    }
    let listen: SocketAddr = listen.parse().context("bad listen addr")?;
    let server = tunnel_server::Server::start(tunnel_server::Config {
        listen,
        data_dir,
        workers,
        quiet,
    })?;
    server.wait();
    Ok(())
}
