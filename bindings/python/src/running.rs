use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::{exceptions, PyObjectWithToken};

use jail as native;
use stopped::StoppedJail;

#[pyclass]
pub struct RunningJail {
    inner: native::RunningJail,
    // As Python keeps its own reference counter, and we can't be sure that
    // that reference will be destroyed when we stop or kill the Jail, we have
    // to keep track of that ourselves.
    dead: bool,
    token: PyToken,
}

impl RunningJail {
    pub fn create(token: PyToken, inner: native::RunningJail) -> Self {
        RunningJail { inner, dead: false, token }
    }
}

#[pymethods]
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
    fn get_ips(&self) -> PyResult<Vec<String>> {
        Ok(self
            .inner
            .ips()
            .map_err(|_| exceptions::SystemError::py_err("Could not get IP Addresses"))?
            .iter()
            .map(|addr| format!("{}", addr))
            .collect())
    }

    #[getter]
    fn get_parameters(&self) -> PyResult<HashMap<String, PyObject>> {
        Ok(self
            .inner
            .params()
            .map_err(|_| exceptions::SystemError::py_err("Could not get parameters"))?
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
            return Err(exceptions::ValueError::py_err(
                "The RunningJail instance is no longer live",
            ));
        }

        let inner = self
            .inner
            .clone()
            .stop()
            .map_err(|_| exceptions::SystemError::py_err("Jail stop failed"))?;
        self.dead = true;
        self.py().init(|token| StoppedJail::create(token, inner))
    }

    /// Kill the Jail.
    fn kill(&mut self) -> PyResult<()> {
        if self.dead {
            return Err(exceptions::ValueError::py_err(
                "The RunningJail instance is no longer live",
            ));
        }

        self.inner
            .clone()
            .kill()
            .map_err(|_| exceptions::SystemError::py_err("Jail stop failed"))?;
        self.dead = true;
        Ok(())
    }

    /// Get RACCT resource accounting information
    #[getter]
    fn get_racct_usage(&self) -> PyResult<HashMap<String, usize>> {
        if self.dead {
            return Err(exceptions::ValueError::py_err(
                "The RunningJail instance is no longer live",
            ));
        }

        let usage = self.inner.racct_statistics();
        let usage_map = usage.map_err(|e| match e {
            native::JailError::RctlError(rctl::Error::InvalidKernelState(s)) => match s {
                rctl::State::Disabled => exceptions::SystemError::py_err(
                    "Resource accounting is disabled. To enable resource \
                     accounting, set the `kern.racct.enable` tunable to 1.",
                ),
                rctl::State::NotPresent => exceptions::SystemError::py_err(
                    "Resource accounting is not enabled in the kernel. \
                     This feature requires the kernel to be compiled with \
                     `OPTION RACCT` set. Current GENERIC kernels should \
                     have this option set.",
                ),
                rctl::State::Enabled => exceptions::SystemError::py_err(
                    "rctl::Error::InvalidKernelState returned but state \
                     is enabled. This really shouldn't happen.",
                ),
                rctl::State::Jailed => exceptions::SystemError::py_err(
                    "Resource accounting isn't available in a jail.",
                ),
            },
            _ => exceptions::SystemError::py_err("Could not get RACCT accounting information"),
        })?;

        Ok(usage_map
            .iter()
            .map(|(resource, metric)| (format!("{}", resource), *metric))
            .collect())
    }

    fn attach(&self) -> PyResult<()> {
        self.inner
            .attach()
            .map_err(|_| exceptions::SystemError::py_err("jail_attach failed"))
    }

    fn defer_cleanup(&self) -> PyResult<()> {
        self.inner
            .defer_cleanup()
            .map_err(|_| exceptions::SystemError::py_err("Could not clear persist flag"))
    }
}
