use param;
use sysctl;

use std::io;

/// An enum for error types of the Jail.
///
/// Implements the `Fail` trait of the `failure` crate.
#[derive(Fail, Debug)]
pub enum JailError {
    #[fail(display = "An IO Error occurred: {:?}", _0)]
    IoError(#[cause] io::Error),

    #[fail(display = "jail_get syscall failed. The error message returned was: {}", _0)]
    JailGetError(String),

    #[fail(display = "jail_set syscall failed. The error message returned was: {}", _0)]
    JailSetError(String),

    #[fail(display = "invalid return code from jail_remove")]
    JailRemoveFailed,

    #[fail(display = "Path not given")]
    PathNotGiven,

    #[fail(display = "No such parameter: {}", _0)]
    NoSuchParameter(String),

    #[fail(display = "Generic sysctl error: {:?}", _0)]
    SysctlError(#[cause] sysctl::SysctlError),

    #[fail(display = "Could not get parameter type: {:?}", _0)]
    ParameterTypeError(#[cause] sysctl::SysctlError),

    #[fail(display = "Could not get string parameter length: {:?}", _0)]
    ParameterStringLengthError(#[cause] sysctl::SysctlError),

    #[fail(display = "Could not get structure parameter length: {:?}", _0)]
    ParameterStructLengthError(#[cause] sysctl::SysctlError),

    #[fail(display = "Could not determine maximum number of IP addresses per family")]
    JailMaxAfIpsFailed(#[cause] sysctl::SysctlError),

    #[fail(display = "Parameter string length returned ('{}') is not a number.", _0)]
    ParameterLengthNaN(String),

    #[fail(display = "Parameter type not supported: {:?}", _0)]
    ParameterTypeUnsupported(sysctl::CtlType),

    #[fail(
        display = "Unexpected parameter type for '{}': expected {:?}, but got {:?}",
        name,
        expected,
        got
    )]
    UnexpectedParameterType {
        name: String,
        expected: sysctl::CtlType,
        got: param::Value,
    },

    #[fail(display = "Failed to unpack parameter.")]
    ParameterUnpackError,

    #[fail(display = "Could not serialize value to bytes")]
    SerializeFailed,
}

impl JailError {
    pub fn from_errno() -> Self {
        JailError::IoError(io::Error::last_os_error())
    }
}
