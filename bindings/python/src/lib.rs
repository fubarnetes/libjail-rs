#![feature(specialization, const_fn)]
extern crate jail;
extern crate pyo3;
extern crate rctl;

use pyo3::prelude::*;

use jail as native;
mod child;
mod error;
mod param;
mod running;
mod stopped;
mod jls;

use child::Child;
use running::RunningJail;
use stopped::StoppedJail;
use jls::Jls;

#[pyclass]
struct JailError {
    inner: native::JailError,
    token: PyToken,
}

#[pymethods]
impl JailError {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{}", self.inner))
    }
}

#[pymodinit(_jail)]
fn jail_modinit(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RunningJail>()?;
    m.add_class::<StoppedJail>()?;
    m.add_class::<Child>()?;
    m.add_class::<Jls>()?;

    Ok(())
}
