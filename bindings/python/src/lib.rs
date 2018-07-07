#![feature(proc_macro, proc_macro_path_invoc, specialization, const_fn)]
extern crate jail;
extern crate pyo3;

use pyo3::prelude::*;
use pyo3::py::{class, methods, modinit};

use jail as native;

#[class]
struct JailError {
    inner: native::JailError,
    token: PyToken,
}

#[methods]
impl JailError {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{}", self.inner))
    }
}

#[class]
struct RunningJail {
    inner: native::RunningJail,
    token: PyToken,
}

#[methods]
impl RunningJail {
    #[new]
    fn __new__(obj: &PyRawObject, jid: i32) -> PyResult<()> {
        obj.init(|token| RunningJail {
            inner: native::RunningJail::from_jid(jid),
            token,
        })
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self.inner))
    }

}

#[class]
struct StoppedJail {
    inner: native::StoppedJail,
    token: PyToken,
}

#[methods]
impl StoppedJail {
    #[new]
    fn __new__(obj: &PyRawObject, path: String) -> PyResult<()> {
        obj.init(|token| StoppedJail {
            inner: native::StoppedJail::new(path),
            token,
        })
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self.inner))
    }

    fn start(&self) -> PyResult<i32> {
        let running = self.inner
            .clone()
            .start()
            .map_err(|_| exc::SystemError::new("Jail start failed"))?;
        Ok(running.jid)
    }
}

#[modinit(_jail)]
fn init_mod(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RunningJail>()?;
    m.add_class::<StoppedJail>()?;
    m.add_class::<JailError>()?;

    Ok(())
}
