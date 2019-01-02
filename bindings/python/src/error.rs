use pyo3::exceptions;
use pyo3::prelude::*;

use std::ops::{Deref, DerefMut};

use native;

pub struct JailError(native::JailError);

impl Deref for JailError {
    type Target = native::JailError;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for JailError {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<native::JailError> for JailError {
    fn from(err: native::JailError) -> Self {
        JailError(err)
    }
}

impl Into<PyErr> for JailError {
    fn into(self) -> PyErr {
        PyErr::new::<exceptions::SystemError, String>(format!("{}", self.0))
    }
}
