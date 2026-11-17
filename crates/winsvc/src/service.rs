//! Обёртка над диспетчером SCM (`windows-service`).

use std::ffi::OsString;
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use windows_service::service::{
    PowerEventParam, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

use crate::ServiceEvent;

type Body = Box<dyn FnOnce(Receiver<ServiceEvent>) -> Result<()> + Send>;

/// Имя и тело службы: `service_main` вызывается SCM без контекста.
static BODY: Mutex<Option<(String, Body)>> = Mutex::new(None);
/// Ошибка тела/регистрации — вернём её из `run_as_service`.
static RESULT: Mutex<Option<anyhow::Error>> = Mutex::new(None);

/// ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: процесс запущен не SCM.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

define_windows_service!(ffi_service_main, service_main);

/// Запускает процесс как службу `name`: блокирует, пока служба не
/// остановится. `body` получает события SCM; после [`ServiceEvent::Stop`] /
/// [`ServiceEvent::Shutdown`] оно должно вернуться. Ошибка `body` → служба
/// завершается с кодом 1 (SCM применит политику восстановления) и
/// возвращается отсюда.
pub fn run_as_service<F>(name: &str, body: F) -> Result<()>
where
    F: FnOnce(Receiver<ServiceEvent>) -> Result<()> + Send + 'static,
{
    *BODY.lock().unwrap() = Some((name.to_string(), Box::new(body)));
    if let Err(e) = service_dispatcher::start(name, ffi_service_main) {
        BODY.lock().unwrap().take();
        if let windows_service::Error::Winapi(io) = &e
            && io.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            return Err(anyhow!(
                "процесс запущен не диспетчером служб: для ручного запуска используйте `tunnel-daemon console`"
            ));
        }
        return Err(e).context("StartServiceCtrlDispatcher");
    }
    match RESULT.lock().unwrap().take() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn status(state: ServiceState, exit: ServiceExitCode, wait: Duration) -> ServiceStatus {
    let controls_accepted = if state == ServiceState::Running {
        ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN
            | ServiceControlAccept::POWER_EVENT
    } else {
        ServiceControlAccept::empty()
    };
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted,
        exit_code: exit,
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_body() {
        *RESULT.lock().unwrap() = Some(e);
    }
}

fn run_body() -> Result<()> {
    let (name, body) = BODY
        .lock()
        .unwrap()
        .take()
        .context("тело службы не задано")?;
    let (tx, rx) = mpsc::channel();
    // хэндл статуса появляется после регистрации — обработчику он нужен для StopPending
    let handle_slot: std::sync::Arc<Mutex<Option<ServiceStatusHandle>>> = Default::default();
    let slot = handle_slot.clone();
    let handler = move |ctl: ServiceControl| -> ServiceControlHandlerResult {
        let ev = match ctl {
            ServiceControl::Stop => Some(ServiceEvent::Stop),
            ServiceControl::Shutdown => Some(ServiceEvent::Shutdown),
            ServiceControl::PowerEvent(
                PowerEventParam::ResumeAutomatic | PowerEventParam::ResumeSuspend,
            ) => Some(ServiceEvent::Resume),
            ServiceControl::PowerEvent(_) | ServiceControl::Interrogate => None,
            _ => return ServiceControlHandlerResult::NotImplemented,
        };
        if let Some(ev) = ev {
            if matches!(ev, ServiceEvent::Stop | ServiceEvent::Shutdown)
                && let Some(h) = *slot.lock().unwrap()
            {
                let _ = h.set_service_status(status(
                    ServiceState::StopPending,
                    ServiceExitCode::Win32(0),
                    Duration::from_secs(15),
                ));
            }
            let _ = tx.send(ev);
        }
        ServiceControlHandlerResult::NoError
    };
    let handle = service_control_handler::register(&name, handler)
        .context("RegisterServiceCtrlHandlerEx")?;
    *handle_slot.lock().unwrap() = Some(handle);
    handle
        .set_service_status(status(
            ServiceState::Running,
            ServiceExitCode::Win32(0),
            Duration::ZERO,
        ))
        .context("SetServiceStatus(Running)")?;

    let res = body(rx);
    let exit = match res {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => ServiceExitCode::ServiceSpecific(1),
    };
    let _ = handle.set_service_status(status(ServiceState::Stopped, exit, Duration::ZERO));
    res
}
