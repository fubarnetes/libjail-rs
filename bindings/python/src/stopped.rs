use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::PyObjectWithToken;
use pyo3::exceptions;

use jail as native;
use running::RunningJail;
use param::parameter_hashmap;

#[pyclass]
pub struct StoppedJail {
    inner: native::StoppedJail,
    token: PyToken,
}

impl StoppedJail {
    pub fn create(token: PyToken, inner: native::StoppedJail) -> Self {
        StoppedJail { inner, token }
    }
}

#[pymethods]
impl StoppedJail {
    #[new]
    fn __new__(
        obj: &PyRawObject,
        path: String,
        name: Option<String>,
        parameters: Option<&PyDict>,
    ) -> PyResult<()> {
        let mut inner = native::StoppedJail::new(path);
        inner.name = name;

        if let Some(params) = parameters {
            inner.params = parameter_hashmap(params)?;
        }

        obj.init(|token| StoppedJail { inner, token })
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self.inner))
    }

    #[getter]
    fn get_parameters(&self) -> PyResult<HashMap<String, PyObject>> {
        Ok(self
            .inner
            .params
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

    #[setter]
    fn set_parameters(&mut self, dict: &PyDict) -> PyResult<()> {
        self.inner.params = parameter_hashmap(dict)?;
        Ok(())
    }

    fn start(&self) -> PyResult<Py<RunningJail>> {
        let inner = self
            .inner
            .clone()
            .start()
            .map_err(|_| exceptions::SystemError::py_err("Jail start failed"))?;
        self.py().init(|token| RunningJail::create(token, inner))
    }
}
