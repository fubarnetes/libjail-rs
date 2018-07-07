#![feature(proc_macro, proc_macro_path_invoc, specialization, const_fn)]
extern crate jail;
extern crate pyo3;
extern crate rctl;

use std::collections::HashMap;

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
    // As Python keeps its own reference counter, and we can't be sure that
    // that reference will be destroyed when we stop or kill the Jail, we have
    // to keep track of that ourselves.
    dead: bool,
    token: PyToken,
}

#[methods]
impl RunningJail {
    #[new]
    fn __new__(obj: &PyRawObject, jid: i32) -> PyResult<()> {
        obj.init(|token| RunningJail {
            inner: native::RunningJail::from_jid(jid),
            dead: false,
            token,
        })
    }

    /// Return a String representation of the Jail
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self.inner))
    }

    #[getter]
    /// The Jail ID
    fn get_jid(&self) -> PyResult<i32> {
        Ok(self.inner.jid)
    }

    #[getter]
    fn get_parameters(&self) -> PyResult<HashMap<String, PyObject>> {
        println!("parameter getter");

        Ok(self
            .inner
            .params()
            .map_err(|_| exc::SystemError::new("Could not get parameters"))?
            .iter()
            .filter_map(|(key, value)| {
                let object = match value {
                    native::param::Value::Int(i) => Some(i.into_object(self.py())),
                    native::param::Value::String(s) => Some(s.into_object(self.py())),
                    native::param::Value::Ipv4Addrs(addrs) => Some(
                        addrs
                            .iter()
                            .map(|addr| format!("{}", addr))
                            .collect::<Vec<String>>()
                            .into_object(self.py()),
                    ),
                    native::param::Value::Ipv6Addrs(addrs) => Some(
                        addrs
                            .iter()
                            .map(|addr| format!("{}", addr))
                            .collect::<Vec<String>>()
                            .into_object(self.py()),
                    ),
                    _ => None,
                };

                object.map(|x| (key.clone(), x.into_object(self.py())))
            })
            .collect())
    }

    /// Stop the Jail, returning a StoppedJail instance with all properties,
    /// resource limits, etc.
    fn stop(&mut self) -> PyResult<Py<StoppedJail>> {
        if self.dead {
            return Err(exc::ValueError::new(
                "The RunningJail instance is no longer live",
            ));
        }

        let inner = self
            .inner
            .clone()
            .stop()
            .map_err(|_| exc::SystemError::new("Jail stop failed"))?;
        self.dead = true;
        self.py().init(|token| StoppedJail { inner, token })
    }

    /// Kill the Jail.
    fn kill(&mut self) -> PyResult<()> {
        if self.dead {
            return Err(exc::ValueError::new(
                "The RunningJail instance is no longer live",
            ));
        }

        self.inner
            .clone()
            .kill()
            .map_err(|_| exc::SystemError::new("Jail stop failed"))?;
        self.dead = true;
        Ok(())
    }

    /// Get RACCT resource accounting information
    #[getter]
    fn get_racct_usage(&self) -> PyResult<HashMap<String, usize>> {
        if self.dead {
            return Err(exc::ValueError::new(
                "The RunningJail instance is no longer live",
            ));
        }

        let usage = self.inner.racct_statistics();
        let usage_map = usage.map_err(|e| match e {
            native::JailError::RctlError(rctl::Error::InvalidKernelState(s)) => match s {
                rctl::State::Disabled => exc::SystemError::new(
                    "Resource accounting is disabled. To enable resource \
                     accounting, set the `kern.racct.enable` tunable to 1.",
                ),
                rctl::State::NotPresent => exc::SystemError::new(
                    "Resource accounting is not enabled in the kernel. \
                     This feature requires the kernel to be compiled with \
                     `OPTION RACCT` set. Current GENERIC kernels should \
                     have this option set.",
                ),
                rctl::State::Enabled => exc::SystemError::new(
                    "rctl::Error::InvalidKernelState returned but state \
                     is enabled. This really shouldn't happen.",
                ),
            },
            _ => exc::SystemError::new("Could not get RACCT accounting information"),
        })?;

        Ok(usage_map
            .iter()
            .map(|(resource, metric)| (format!("{}", resource), *metric))
            .collect())
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

    fn start(&self) -> PyResult<Py<RunningJail>> {
        let inner = self
            .inner
            .clone()
            .start()
            .map_err(|_| exc::SystemError::new("Jail start failed"))?;
        self.py().init(|token| RunningJail {
            inner,
            dead: false,
            token,
        })
    }
}

#[modinit(_jail)]
fn init_mod(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<RunningJail>()?;
    m.add_class::<StoppedJail>()?;
    m.add_class::<JailError>()?;

    Ok(())
}
