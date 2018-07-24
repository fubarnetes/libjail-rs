use libc;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;
use std::str;

use std::path;

use param;
use JailError;

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
    (mut $name:expr) => {
        libc::iovec {
            iov_base: $name.as_mut_ptr() as *mut libc::c_void,
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
    params: HashMap<String, param::Value>,
) -> Result<i32, JailError> {
    trace!("jail_create(path={:?}, params={:?})", path, params);
    let pathstr = CString::new(path.as_os_str().to_str().unwrap())
        .unwrap()
        .into_bytes_with_nul();
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };

    let mut jiov = vec![
        iovec!(b"path\0"),
        iovec!(pathstr),
        iovec!(b"errmsg\0"),
        iovec!(mut errmsg),
        iovec!(b"persist\0"),
        iovec!(),
    ];

    let parameter_array: HashMap<CString, Vec<u8>> = params
        .iter()
        .filter_map(|(key, value)| {
            Some((
                CString::new(key.clone()).ok()?,
                value.clone().as_bytes().ok()?,
            ))
        })
        .collect();

    let mut param_jiov: Vec<libc::iovec> = parameter_array
        .iter()
        .flat_map(|(key, value)| {
            vec![
                iovec!(key.as_ptr(), key.as_bytes_with_nul().len()),
                iovec!(value.as_ptr() as *const libc::c_void, value.len()),
            ]
        })
        .collect();

    jiov.append(&mut param_jiov);

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

/// Test if a jail exists. Returns
pub fn jail_exists(jid: i32) -> bool {
    trace!("jail_exists({})", jid);
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };
    let mut jiov: Vec<libc::iovec> = vec![
        iovec!(b"jid\0"),
        iovec!(&jid as *const _, mem::size_of::<i32>()),
        iovec!(b"errmsg\0"),
        iovec!(errmsg.as_mut_ptr(), errmsg.len()),
    ];

    let retjid = unsafe {
        libc::jail_get(
            jiov[..].as_mut_ptr() as *mut libc::iovec,
            jiov.len() as u32,
            JailFlags::empty().bits,
        )
    };

    jid == retjid
}

/// Clear the persist flag
#[cfg(target_os = "freebsd")]
pub fn jail_clearpersist(jid: i32) -> Result<(), JailError> {
    trace!("jail_clearpersist({})", jid);
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };
    let mut jiov: Vec<libc::iovec> = vec![
        iovec!(b"jid\0"),
        iovec!(&jid as *const _, mem::size_of::<i32>()),
        iovec!(b"errmsg\0"),
        iovec!(errmsg.as_mut_ptr(), errmsg.len()),
        iovec!(b"nopersist\0"),
        iovec!(),
    ];

    let jid = unsafe {
        libc::jail_set(
            jiov[..].as_mut_ptr() as *mut libc::iovec,
            jiov.len() as u32,
            JailFlags::UPDATE.bits,
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
        _ => Ok(()),
    }
}

/// Get the `jid` of a jail given the name.
///
/// This function attempts to parse the name into an `i32` first, which is
/// returned if successful.
#[cfg(target_os = "freebsd")]
pub fn jail_getid(name: &str) -> Result<i32, JailError> {
    trace!("jail_getid(name={:?})", name);
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

/// Get the next `jid` given the last `jid`.
#[cfg(target_os = "freebsd")]
pub fn jail_nextjid(lastjid: i32) -> Result<i32, JailError> {
    trace!("jail_nextjid(lastjid={})", lastjid);
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };

    let mut jiov = vec![
        iovec!(b"lastjid\0"),
        iovec!(&lastjid as *const _, mem::size_of::<i32>()),
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
    trace!("jail_remove(jid={})", jid);
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
        let mut params: HashMap<String, param::Value> = HashMap::new();
        params.insert(
            "name".into(),
            param::Value::String("testjail_create_remove".into()),
        );
        let jid = jail_create(Path::new("/rescue"), params).expect("could not start jail");
        jail_remove(jid).expect("could not remove jail");
    }

    #[test]
    fn id() {
        let mut params: HashMap<String, param::Value> = HashMap::new();
        params.insert("name".into(), param::Value::String("testjail_getid".into()));
        let target_jid = jail_create(Path::new("/rescue"), params).expect("could not start jail");
        let jid = jail_getid("testjail_getid").expect("could not get ID of test jail");
        assert_eq!(jid, target_jid);
        jail_remove(jid).expect("could not remove jail");
    }
}
