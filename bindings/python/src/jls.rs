use pyo3::prelude::*;
use pyo3::{PyIterProtocol, PyObjectWithToken};

use jail as native;
use running::RunningJail;

#[pyclass]
pub struct Jls {
    token: PyToken,
    iter: native::RunningJailIter,
}

#[pymethods]
impl Jls {
    #[new]
    fn __new__(obj: &PyRawObject) -> PyResult<()> {
        obj.init(|token| Jls {
            iter: native::RunningJail::all(),
            token,
        })
    }
}

#[pyproto]
impl PyIterProtocol for Jls {
    fn __iter__(&mut self) -> PyResult<PyObject> {
        self.iter = native::RunningJail::all();
        Ok(self.into())
    }

    fn __next__(&mut self) -> PyResult<Option<Py<RunningJail>>> {
        match self.iter.next() {
            None => Ok(None),
            Some(next) => Ok(Some(
                self.py().init(|token| RunningJail::create(token, next))?,
            )),
        }
    }
}
