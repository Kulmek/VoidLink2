//! Single-instance замок движка — живёт в `tunnel-ipc` ([`tunnel_ipc::lock`]):
//! его берут и демон, и embedded TUI / `run` клиента, а `tunnel-client` не
//! может зависеть от `tunnel-daemon` (демон сам зависит от клиента).

pub use tunnel_ipc::lock::{InstanceLock, LOCK_FILE, LockError, MUTEX_NAME};
