use JailError;

use sysctl::{Ctl, CtlValue, SysctlError};

/// Test if VIMAGE support is present.
pub fn check_support() -> Result<bool, JailError> {
    let ctl = Ctl::new("kern.features.vimage");

    if let Err(SysctlError::IoError(ref e)) = ctl {
        if e.kind() == std::io::ErrorKind::NotFound {
            return Ok(false);
        }
    }

    if let CtlValue::Int(1) = ctl
        .map_err(JailError::SysctlError)?
        .value()
        .map_err(JailError::SysctlError)?
    {
        return Ok(true);
    }

    Ok(false)
}
