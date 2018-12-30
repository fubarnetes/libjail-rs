use pyo3::prelude::*;
use pyo3::{exceptions, PyObjectWithToken};

use std::ops::{Deref, DerefMut};
use std::os::unix::process::ExitStatusExt;

#[pyclass]
pub struct ExitStatus {
    token: PyToken,
    inner: std::process::ExitStatus,
}

impl Deref for ExitStatus {
    type Target = std::process::ExitStatus;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ExitStatus {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[pymethods]
impl ExitStatus {
    fn __str__(&self) -> PyResult<String> {
        Ok(match self.inner.code() {
            Some(c) => match self.inner.success() {
                true => format!("Process terminated successfully."),
                false => format!("Process terminated with code {}", c),
            },
            None => match self.inner.signal() {
                Some(s) => format!("Process terminated by signal {}", s),
                None => format!("Unkown process exit status"),
            },
        })
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(match self.inner.code() {
            Some(c) => match self.inner.success() {
                true => format!("<ExitStatus Success>"),
                false => format!("<ExitStatus code={}>", c),
            },
            None => match self.inner.signal() {
                Some(s) => format!("<ExitStatus signal={}>", s),
                None => format!("<ExitStatus unknown>"),
            },
        })
    }

    #[getter]
    fn get_success(&self) -> PyResult<bool> {
        Ok(self.inner.success())
    }

    #[getter]
    fn get_code(&self) -> PyResult<Option<i32>> {
        Ok(self.inner.code())
    }

    #[getter]
    fn get_signal(&self) -> PyResult<Option<i32>> {
        Ok(self.inner.signal())
    }
}

#[pyclass]
pub struct Child {
    token: PyToken,
    inner: std::process::Child,
}

impl Deref for Child {
    type Target = std::process::Child;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Child {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Child {
    pub fn create(token: PyToken, inner: std::process::Child) -> Self {
        Child { token, inner }
    }
}

#[pymethods]
impl Child {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("<Child: {:?}>", self.inner))
    }

    fn kill(&mut self) -> PyResult<()> {
        self.inner.kill().map_err(|e| match e.kind() {
            std::io::ErrorKind::InvalidInput => {
                exceptions::IOError::py_err("child already exited.")
            }
            _ => PyErr::new::<exceptions::IOError, String>(format!("{}", e)),
        })
    }

    #[getter]
    fn get_id(&mut self) -> PyResult<u32> {
        Ok(self.inner.id())
    }

    fn wait(&mut self) -> PyResult<Py<ExitStatus>> {
        let status = self
            .inner
            .wait()
            .map_err(|e| PyErr::new::<exceptions::IOError, String>(format!("{}", e)))?;

        self.py().init(|token| ExitStatus {
            token,
            inner: status,
        })
    }

    fn try_wait(&mut self) -> PyResult<Option<Py<ExitStatus>>> {
        self.inner
            .try_wait()
            .map_err(|e| PyErr::new::<exceptions::IOError, String>(format!("{}", e)))?
            .map(|s| self.py().init(|token| ExitStatus { token, inner: s }))
            .map_or(Ok(None), |v| v.map(Some))
    }
}
