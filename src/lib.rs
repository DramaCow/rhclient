use base64::{engine::general_purpose::STANDARD, Engine};
use pyo3::exceptions::{PyRuntimeError, PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use serde_json::json;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use tokio::runtime::Builder;
use tokio::sync::{broadcast, mpsc};

struct Worker {
    shutdown: broadcast::Sender<bool>,
    done: Mutex<bool>,
    changed: Condvar,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Worker {
    fn close(&self, timeout: Duration) -> Result<(), &'static str> {
        let start = Instant::now();
        let _ = self.shutdown.send(true);
        let mut done = self.done.lock().unwrap_or_else(|e| e.into_inner());
        while !*done {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err("Tunnel did not stop before the close deadline");
            }
            done = self
                .changed
                .wait_timeout(done, remaining)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        if let Some(handle) = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = handle.join();
        }
        Ok(())
    }
}

#[pyclass(module = "rhclient._native")]
struct _Tunnel {
    worker: Arc<Worker>,
}

fn address_valid(address: &str) -> bool {
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    let host_valid = if host.starts_with('[') && host.ends_with(']') {
        host[1..host.len() - 1]
            .parse::<std::net::Ipv6Addr>()
            .is_ok()
    } else {
        host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
    };
    host_valid && port.parse::<u16>().is_ok_and(|p| p > 0)
}

#[pymethods]
impl _Tunnel {
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        server_addr: String,
        local_addr: String,
        service: String,
        token: String,
        server_public_key: String,
        heartbeat_timeout: u64,
        retry_interval: u64,
    ) -> PyResult<Self> {
        if !address_valid(&server_addr) || !address_valid(&local_addr) {
            return Err(PyValueError::new_err(
                "Addresses must be host:port pairs with a nonzero port",
            ));
        }
        if service.is_empty()
            || !service
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(PyValueError::new_err(
                "Service must contain only letters, digits, underscores or hyphens",
            ));
        }
        if token.is_empty() || heartbeat_timeout == 0 || retry_interval == 0 {
            return Err(PyValueError::new_err(
                "Token and positive heartbeat/retry intervals are required",
            ));
        }
        if !STANDARD
            .decode(&server_public_key)
            .is_ok_and(|key| key.len() == 32)
        {
            return Err(PyValueError::new_err(
                "Server public key must be a base64-encoded 32-byte key",
            ));
        }
        let configuration = json!({"client": {
            "remote_addr": server_addr, "heartbeat_timeout": heartbeat_timeout,
            "retry_interval": retry_interval,
            "transport": {"type": "noise", "noise": {
                "pattern": "Noise_NK_25519_ChaChaPoly_BLAKE2s",
                "remote_public_key": server_public_key
            }},
            "services": {service: {"local_addr": local_addr, "token": token, "type": "tcp"}}
        }});
        let configuration = toml::Value::try_from(configuration)
            .map_err(|_| PyValueError::new_err("Unable to encode tunnel configuration"))?;
        let configuration = toml::to_string(&configuration)
            .map_err(|_| PyValueError::new_err("Unable to encode tunnel configuration"))?;
        py.detach(move || {
            let mut file = NamedTempFile::new().map_err(|_| {
                PyRuntimeError::new_err("Unable to create private tunnel configuration")
            })?;
            file.write_all(configuration.as_bytes()).map_err(|_| {
                PyRuntimeError::new_err("Unable to write private tunnel configuration")
            })?;
            let (shutdown, shutdown_rx) = broadcast::channel(1);
            let worker = Arc::new(Worker {
                shutdown,
                done: Mutex::new(false),
                changed: Condvar::new(),
                thread: Mutex::new(None),
            });
            let background = worker.clone();
            let (ready_tx, mut ready_rx) = mpsc::channel(1);
            let handle = thread::Builder::new()
                .name("rhclient".into())
                .spawn(move || {
                    struct Finished(Arc<Worker>);
                    impl Drop for Finished {
                        fn drop(&mut self) {
                            *self.0.done.lock().unwrap_or_else(|e| e.into_inner()) = true;
                            self.0.changed.notify_all();
                        }
                    }
                    let _finished = Finished(background);
                    let runtime = match Builder::new_current_thread().enable_all().build() {
                        Ok(runtime) => runtime,
                        Err(_) => {
                            let _ = ready_tx.blocking_send(false);
                            return;
                        }
                    };
                    runtime.block_on(async {
                        if rathole::Config::from_file(file.path()).await.is_err() {
                            let _ = ready_tx.send(false).await;
                            return;
                        }
                        let args = rathole::Cli {
                            config_path: Some(file.path().to_owned()),
                            client: true,
                            ..Default::default()
                        };
                        let _ = ready_tx.send(true).await;
                        let _ = rathole::run(args, shutdown_rx).await;
                    });

                    runtime.shutdown_timeout(Duration::from_secs(1));
                    drop(file);
                })
                .map_err(|_| PyRuntimeError::new_err("Unable to start tunnel supervisor"))?;
            *worker.thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
            if ready_rx.blocking_recv() != Some(true) {
                let _ = worker.close(Duration::from_secs(5));
                return Err(PyRuntimeError::new_err(
                    "Unable to initialise tunnel runtime",
                ));
            }
            Ok(Self { worker })
        })
    }

    #[getter]
    fn running(&self) -> bool {
        !*self.worker.done.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[pyo3(signature = (timeout=5.0))]
    fn close(&self, py: Python<'_>, timeout: f64) -> PyResult<()> {
        if !timeout.is_finite() || !(0.0..=300.0).contains(&timeout) {
            return Err(PyValueError::new_err(
                "Close timeout must be finite and between 0 and 300 seconds",
            ));
        }
        py.detach(|| self.worker.close(Duration::from_secs_f64(timeout)))
            .map_err(PyTimeoutError::new_err)
    }
}

impl Drop for _Tunnel {
    fn drop(&mut self) {
        let _ = self.worker.shutdown.send(true);
    }
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<_Tunnel>()?;
    Ok(())
}
