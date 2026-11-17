use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tunnel_daemon::cli::{self, Mode};
use tunnel_daemon::service;

fn main() -> ExitCode {
    let mode = match cli::parse(std::env::args().skip(1)) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("ошибка: {e}\n\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };
    let dir = |d: Option<std::path::PathBuf>| d.unwrap_or_else(tunnel_daemon::default_data_dir);
    let res = match mode {
        Mode::Help => {
            print!("{}", cli::USAGE);
            Ok(())
        }
        Mode::Console { debug, data_dir } => {
            // Остановка — Ctrl+C (процесс завершается целиком); флаг для
            // интеграции с обработчиком сигналов/консоли.
            let stop = Arc::new(AtomicBool::new(false));
            service::run_console(&dir(data_dir), debug, service::NullBackend, stop)
        }
        Mode::Service { data_dir } => service::run_service(&dir(data_dir)),
        Mode::Install => service::install(),
        Mode::Uninstall { purge } => service::uninstall(purge),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ошибка: {e}");
            ExitCode::FAILURE
        }
    }
}
