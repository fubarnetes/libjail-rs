extern crate libc;

extern crate errno;
use errno::errno;

use std::ffi::{CStr, CString};
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

pub fn jail_getname(jid: i32) -> Result<String, String> {
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
            0 => Err(format!("{}", errno())),
            _ => Err(err.to_string_lossy().into_owned()),
        },
        _ => Ok(name.to_string_lossy().into_owned()),
    }
}

pub fn jail_getid(name: &str) -> Result<i32, String> {
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
            0 => Err(format!("{}", errno())),
            _ => Err(err.to_string_lossy().into_owned()),
        },
        _ => Ok(jid),
    }
}
