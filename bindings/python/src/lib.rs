#![feature(proc_macro, proc_macro_path_invoc, specialization, const_fn)]
extern crate jail;
extern crate pyo3;

use pyo3::prelude::*;
use pyo3::py::{class, methods, modinit};

use jail::RunningJail as NativeRunningJail;
use jail::StoppedJail as NativeStoppedJail;

#[class]
struct RunningJail {
    inner: NativeRunningJail,
    token: PyToken,
}

#[methods]
impl RunningJail {
    #[new]
    fn __new__(obj: &PyRawObject, jid: i32) -> PyResult<()> {
        obj.init(|token| RunningJail {
            inner: NativeRunningJail::from_jid(jid),
            token,
        })
    }
}

#[class]
struct StoppedJail {
    inner: NativeStoppedJail,
    token: PyToken,
}

#[methods]
impl StoppedJail {
    #[new]
    fn __new__(obj: &PyRawObject, path: String) -> PyResult<()> {
        obj.init(|token| StoppedJail {
            inner: NativeStoppedJail::new(path),
            token,
        })
    }
}

#[modinit(_jail)]
fn init_mod(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RunningJail>()?;
    m.add_class::<StoppedJail>()?;

    Ok(())
}
