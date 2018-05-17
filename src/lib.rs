//! This is the jail crate.
//!
//! it aims to provide the features exposed by the FreeBSD Jail Library
//! [jail(3)](https://www.freebsd.org/cgi/man.cgi?query=jail&sektion=3&manpath=FreeBSD+11.1-stable)

extern crate libc;

pub mod process;

use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind};
use std::mem;

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
}

/// Get the name of a jail given the jid
///
/// # Examples
///
/// ```
/// let name = jail::jail_getname(1);
/// println!("{:?}", name);
/// ```
#[cfg(target_os = "freebsd")]
pub fn jail_getname(jid: i32) -> Result<String, Error> {
    let mut namebuf: [u8; 256] = unsafe { mem::zeroed() };
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };
    let mut jid = jid;

    let mut jiov: Vec<libc::iovec> = vec![
        iovec!(b"jid\0"),
        iovec!(&mut jid as *mut _, mem::size_of::<i32>()),
        iovec!(b"name\0"),
        iovec!(namebuf.as_mut_ptr(), namebuf.len()),
        iovec!(b"errmsg\0"),
        iovec!(errmsg.as_mut_ptr(), errmsg.len()),
    ];

    let jid = unsafe {
        libc::jail_get(
            jiov[..].as_mut_ptr() as *mut libc::iovec,
            jiov.len() as u32,
            0,
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut i8) };
    let name = unsafe { CStr::from_ptr(namebuf.as_ptr() as *mut i8) };

    match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(Error::last_os_error()),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("{}", err.to_string_lossy()),
            )),
        },
        _ => Ok(name.to_string_lossy().into_owned()),
    }
}

/// Get the `jid` of a jail given the name.
///
/// This function attempts to parse the name into an `i32` first, which is
/// returned if successful.
///
/// # Examples
///
/// ```
/// let name = jail::jail_getid("foobar");
/// println!("{:?}", name);
/// ````
#[cfg(target_os = "freebsd")]
pub fn jail_getid(name: &str) -> Result<i32, Error> {
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
            0,
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut i8) };

    match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(Error::last_os_error()),
            _ => Err(Error::new(
                ErrorKind::Other,
                format!("{}", err.to_string_lossy()),
            )),
        },
        _ => Ok(jid),
    }
}

/// Remove a jail with the given `jid`.
///
/// This will kill all processes belonging to the jail, and remove any children
/// of that jail.
///
/// Examples:
///
/// ```
/// use jail::jail_remove;
///
/// jail_remove(1);
/// ```
pub fn jail_remove(jid: i32) -> Result<(), Error> {
    let ret = unsafe { libc::jail_remove(jid) };
    match ret {
        0 => Ok(()),
        -1 => Err(Error::last_os_error()),
        _ => Err(Error::new(
            ErrorKind::Other,
            "invalid return value from jail_remove",
        )),
    }
}
