use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyInt, PyString};
use pyo3::{exceptions, PyDowncastError};

use jail as native;

pub fn parameter_hashmap(dict: &PyDict) -> PyResult<HashMap<String, native::param::Value>> {
    let (converted, failed): (Vec<_>, Vec<_>) = dict
        .iter()
        .map(|(key, value)| {
            let key: PyResult<&PyString> = key
                .try_into()
                .map_err(|_| exceptions::TypeError::py_err("Parameter key must be a string"));
            let key: PyResult<String> = key.and_then(|k| k.extract());

            let py_string: Result<&PyString, PyDowncastError> = value.try_into();
            let py_num: Result<&PyInt, PyDowncastError> = value.try_into();

            let wrapped_value = if let Ok(string) = py_string {
                string.extract().map(native::param::Value::String)
            } else if let Ok(num) = py_num {
                num.extract().map(native::param::Value::Int)
            } else {
                Err(exceptions::TypeError::py_err(
                    "Only string and integer parameters are supported",
                ))
            };

            (key, wrapped_value)
        })
        .map(|t| match t {
            (Ok(key), Ok(value)) => Ok((key, value)),
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(e),
        })
        .partition(Result::is_ok);

    for e in failed {
        return Err(e.unwrap_err());
    }

    Ok(converted.into_iter().map(Result::unwrap).collect())
}
