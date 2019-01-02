use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use pyo3::{exceptions, PyObjectWithToken};

use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::io::AsRawFd;
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

    fn stdin(&mut self) -> PyResult<&mut std::process::ChildStdin> {
        self.stdin
            .as_mut()
            .ok_or(exceptions::IOError::py_err("Stdin not captured"))
    }

    fn stdout(&mut self) -> PyResult<&mut std::process::ChildStdout> {
        self.stdout
            .as_mut()
            .ok_or(exceptions::IOError::py_err("Stdout not captured"))
    }

    fn stderr(&mut self) -> PyResult<&mut std::process::ChildStderr> {
        self.stderr
            .as_mut()
            .ok_or(exceptions::IOError::py_err("Stderr not captured"))
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

    #[getter]
    fn get_stdin_fd(&mut self) -> PyResult<std::os::unix::io::RawFd> {
        Ok(self.stdin()?.as_raw_fd())
    }

    fn try_wait(&mut self) -> PyResult<Option<Py<ExitStatus>>> {
        self.inner
            .try_wait()
            .map_err(|e| PyErr::new::<exceptions::IOError, String>(format!("{}", e)))?
            .map(|s| self.py().init(|token| ExitStatus { token, inner: s }))
            .map_or(Ok(None), |v| v.map(Some))
    }

    pub fn write_stdin(&mut self, buf: &PyByteArray) -> PyResult<usize> {
        self.stdin()?
            .write(buf.data())
            .map_err(|_| exceptions::IOError::py_err("Could not write to stdin"))
    }

    pub fn write_stdin_str(&mut self, buf: String) -> PyResult<()> {
        self.stdin()?
            .write_all(buf.as_bytes())
            .map_err(|_| exceptions::IOError::py_err("Could not write to stdin"))
    }

    pub fn flush_stdin(&mut self) -> PyResult<()> {
        self.stdin()?
            .flush()
            .map_err(|e| PyErr::new::<exceptions::IOError, String>(format!("{}", e)))
    }

    #[getter]
    fn get_stdout_fd(&mut self) -> PyResult<std::os::unix::io::RawFd> {
        Ok(self.stdout()?.as_raw_fd())
    }

    pub fn read_stdout(&mut self, len: usize) -> PyResult<&PyByteArray> {
        let into: PyResult<Vec<u8>> = {
            let stdout = self.stdout()?;

            let mut into = vec![0; len];
            let read = stdout
                .read(&mut into)
                .map_err(|_| exceptions::IOError::py_err("Could not read from Stdout"))?;
            into.truncate(read);
            Ok(into)
        };

        Ok(PyByteArray::new(self.py(), &into?))
    }

    pub fn readall_stdout_str(&mut self) -> PyResult<String> {
        let stdout = self.stdout()?;

        let mut into = String::new();
        stdout
            .read_to_string(&mut into)
            .map_err(|_| exceptions::IOError::py_err("Could not read from Stdout"))?;

        Ok(into)
    }

    #[getter]
    fn get_stderr_fd(&mut self) -> PyResult<std::os::unix::io::RawFd> {
        Ok(self.stderr()?.as_raw_fd())
    }

    pub fn read_stderr(&mut self, len: usize) -> PyResult<&PyByteArray> {
        let into: PyResult<Vec<u8>> = {
            let stderr = self.stderr()?;

            let mut into = vec![0; len];
            let read = stderr
                .read(&mut into)
                .map_err(|_| exceptions::IOError::py_err("Could not read from Stderr"))?;
            into.truncate(read);
            Ok(into)
        };

        Ok(PyByteArray::new(self.py(), &into?))
    }

    pub fn readall_stderr_str(&mut self) -> PyResult<String> {
        let stderr = self.stderr()?;

        let mut into = String::new();
        stderr
            .read_to_string(&mut into)
            .map_err(|_| exceptions::IOError::py_err("Could not read from Stdout"))?;

        Ok(into)
    }
}
