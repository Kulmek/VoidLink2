use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tunnel_daemon::cli::{self, Mode};
use tunnel_daemon::engine_backend::ConsoleBackend;
use tunnel_daemon::service;
use tunnel_daemon::Level;

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
        Mode::Console { debug, fake, data_dir } => {
            // Остановка — Ctrl+C / SIGTERM: флаг, хаб выходит штатно.
            let stop = Arc::new(AtomicBool::new(false));
            service::install_ctrl_handler(stop.clone());
            if fake {
                service::run_console(&dir(data_dir), debug, |_log| tunnel_daemon::FakeBackend::new(), stop)
            } else {
                // Настоящий движок по client.json каталога данных (нужны права
                // администратора на TUN). Ошибка запуска — останов и выход с ней.
                tunnel_client::engine::set_debug(debug);
                let dir = dir(data_dir);
                let failed = Arc::new(std::sync::Mutex::new(None::<String>));
                let (f, s, d) = (failed.clone(), stop.clone(), dir.clone());
                let r = service::run_console(
                    &dir,
                    debug,
                    move |log| match tunnel_daemon::engine_backend::start_from_dir(&d, log.clone()) {
                        Ok(b) => ConsoleBackend::Live(Box::new(b)),
                        Err(e) => {
                            log(Level::Error, &e);
                            *f.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.clone());
                            s.store(true, std::sync::atomic::Ordering::SeqCst);
                            ConsoleBackend::Failed(e)
                        }
                    },
                    stop,
                );
                match failed.lock().unwrap_or_else(|p| p.into_inner()).take() {
                    Some(e) => Err(e),
                    None => r,
                }
            }
        }
        // Данные службы — %ProgramData%\tunnel (или --data-dir); движок
        // подключит интеграция через фабрику (env: лог, wintun.dll, resume).
        Mode::Service { data_dir } => service::run_service(data_dir.as_deref(), |_env| service::NullBackend),
        Mode::Install => service::install(),
        Mode::Uninstall { purge } => service::uninstall(purge, || Ok(())),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ошибка: {e}");
            ExitCode::FAILURE
        }
    }
}
