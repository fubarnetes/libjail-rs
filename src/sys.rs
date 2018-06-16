use libc;

use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;
use std::str;

use std::path;

use sysctl::CtlType;
use JailError;

use param;

macro_rules! iovec {
    ($value:expr, $size:expr) => {
        libc::iovec {
            iov_base: $value as *mut libc::c_void,
            iov_len: $size,
        }
    };
    ($name:expr) => {
        libc::iovec {
            iov_base: $name.as_ptr() as *mut libc::c_void,
            iov_len: $name.len(),
        }
    };
    () => {
        libc::iovec {
            iov_base: ptr::null::<libc::c_void>() as *mut libc::c_void,
            iov_len: 0,
        }
    };
}

bitflags! {
    pub struct JailFlags : i32 {
        /// Create the Jail if it doesn't exist
        const CREATE = 0x01;

        /// Update parameters of existing Jail
        const UPDATE = 0x02;

        /// Attach to Jail upon creation
        const ATTACH = 0x04;

        /// Allow getting a dying jail
        const DYING = 0x08;
    }
}

/// Create a jail with a specific path
#[cfg(target_os = "freebsd")]
pub fn jail_create(
    path: &path::Path,
    name: Option<&str>,
    hostname: Option<&str>,
) -> Result<i32, JailError> {
    let pathstr = CString::new(path.as_os_str().to_str().unwrap()).unwrap();
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };

    let mut jiov = vec![
        iovec!(b"path\0"),
        iovec!(pathstr.as_ptr(), pathstr.as_bytes().len() + 1),
        iovec!(b"persist\0"),
        iovec!(),
    ];

    if let Some(name) = name {
        jiov.push(iovec!(b"name\0"));
        let namebuf = CString::new(name).unwrap();
        let len = namebuf.as_bytes().len() + 1;
        jiov.push(iovec!(namebuf.into_bytes_with_nul().as_ptr(), len));
    }

    if let Some(hostname) = hostname {
        jiov.push(iovec!(b"host.hostname\0"));
        let namebuf = CString::new(hostname).unwrap();
        let len = namebuf.as_bytes().len() + 1;
        jiov.push(iovec!(namebuf.into_bytes_with_nul().as_ptr(), len));
    }

    jiov.push(iovec!(b"errmsg\0"));
    jiov.push(iovec!(errmsg.as_mut_ptr(), errmsg.len()));

    let jid = unsafe {
        libc::jail_set(
            jiov[..].as_mut_ptr() as *mut libc::iovec,
            jiov.len() as u32,
            JailFlags::CREATE.bits,
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut i8) }
        .to_string_lossy()
        .to_string();

    match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(JailError::from_errno()),
            _ => Err(JailError::JailSetError(err)),
        },
        _ => Ok(jid),
    }
}

/// Get the name of a jail given the jid
#[cfg(target_os = "freebsd")]
pub fn jail_getname(jid: i32) -> Result<String, JailError> {
    match param::get(jid, "name")? {
        param::Value::String(s) => Ok(s),
        unexpected => Err(JailError::UnexpectedParameterType {
            name: "name".to_string(),
            expected: CtlType::String,
            got: unexpected,
        }),
    }
}

/// Get the `jid` of a jail given the name.
///
/// This function attempts to parse the name into an `i32` first, which is
/// returned if successful.
#[cfg(target_os = "freebsd")]
pub fn jail_getid(name: &str) -> Result<i32, JailError> {
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };

    if let Ok(jid) = name.parse::<i32>() {
        return Ok(jid);
    };

    let name = CString::new(name).unwrap().into_bytes_with_nul();

    let mut jiov = vec![
        iovec!(b"name\0"),
        iovec!(name),
        iovec!(b"errmsg\0"),
        iovec!(errmsg.as_mut_ptr(), errmsg.len()),
    ];

    let jid = unsafe {
        libc::jail_get(
            jiov[..].as_mut_ptr() as *mut libc::iovec,
            jiov.len() as u32,
            JailFlags::empty().bits,
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut i8) }
        .to_string_lossy()
        .to_string();

    match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(JailError::from_errno()),
            _ => Err(JailError::JailGetError(err)),
        },
        _ => Ok(jid),
    }
}

/// Remove a jail with the given `jid`.
///
/// This will kill all processes belonging to the jail, and remove any children
/// of that jail.
#[cfg(target_os = "freebsd")]
pub fn jail_remove(jid: i32) -> Result<(), JailError> {
    let ret = unsafe { libc::jail_remove(jid) };
    match ret {
        0 => Ok(()),
        -1 => Err(JailError::from_errno()),
        _ => Err(JailError::JailRemoveFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn create_remove() {
        let jid = jail_create(Path::new("/rescue"), Some("testjail_create_remove"), None)
            .expect("could not start jail");

        jail_remove(jid).expect("could not remove jail");
    }

    #[test]
    fn name() {
        let jid = jail_create(Path::new("/rescue"), Some("testjail_getname"), None)
            .expect("could not start jail");

        let name = jail_getname(jid).expect("could not get name");

        assert_eq!(name, "testjail_getname");

        jail_remove(jid).expect("could not remove jail");
    }

    #[test]
    fn id() {
        let target_jid = jail_create(Path::new("/rescue"), Some("testjail_getid"), None)
            .expect("could not start jail");

        let jid = jail_getid("testjail_getid").expect("could not get ID of test jail");
        assert_eq!(jid, target_jid);
        jail_remove(jid).expect("could not remove jail");
    }
}
