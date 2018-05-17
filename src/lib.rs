//! This is the jail crate.
//!
//! it aims to provide the features exposed by the FreeBSD Jail Library
//! [jail(3)](https://www.freebsd.org/cgi/man.cgi?query=jail&sektion=3&manpath=FreeBSD+11.1-stable)

extern crate libc;

pub mod process;

use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind};
use std::mem;
use std::ptr;

#[macro_use]
extern crate bitflags;

use std::os::unix::ffi::OsStrExt;
use std::path;

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
///
/// # Examples
///
/// ```
/// use std::path::Path;
///
/// let jid = jail::jail_create(Path::new("/tmp"), Some("testjail"), None).unwrap();
/// assert_eq!(jail::jail_getname(jid).unwrap(), "testjail");
/// jail::jail_remove(jid);
/// ```
pub fn jail_create(
    path: &path::Path,
    name: Option<&str>,
    hostname: Option<&str>,
) -> Result<i32, Error> {
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
            JailFlags::empty().bits,
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
            JailFlags::empty().bits,
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

/// Represent a running jail.
#[derive(Clone, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
#[cfg(target_os = "freebsd")]
pub struct Jail {
    /// The `jid` of the jail
    pub jid: Option<i32>,
    pub path: Option<path::PathBuf>,
    pub name: Option<String>,
    pub hostname: Option<String>,
}

impl Default for Jail {
    fn default() -> Jail {
        Jail {
            jid: None,
            path: None,
            name: None,
            hostname: None,
        }
    }
}

impl Jail {
    /// Create a new Jail instance given a path.
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::Jail;
    ///
    /// let j = Jail::new("/rescue");
    /// ```
    pub fn new<P: Into<path::PathBuf>>(path: P) -> Jail {
        let mut ret: Jail = Default::default();
        ret.path = Some(path.into());
        ret
    }

    /// Create a [Jail](struct.Jail.html) instance given a `jid`. No checks
    /// will be performed.
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::Jail;
    ///
    /// let j = Jail::from_jid(42);
    /// ```
    pub fn from_jid(jid: i32) -> Jail {
        let mut ret: Jail = Default::default();
        ret.jid = Some(jid);
        ret
    }

    /// Create a [Jail](struct.Jail.html) given the jail `name`.
    ///
    /// The `jid` will be internally resolved using
    /// [jail_getid](fn.jail_getid.html).
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::Jail;
    ///
    /// let j = Jail::from_name("testjail");
    /// ```
    pub fn from_name(name: &str) -> Result<Jail, Error> {
        jail_getid(name).map(Jail::from_jid)
    }

    /// Return the jail's `name`.
    ///
    /// The name will be internall resolved using
    /// [jail_getname](fn.jail_getname.html).
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::Jail;
    ///
    /// let jail = Jail::from_name("testjail").unwrap();
    /// assert_eq!(jail.name().unwrap(), "testjail");
    /// ```
    pub fn name(self: &Jail) -> Result<String, Error> {
        match self.jid {
            Some(jid) => jail_getname(jid),
            None => Err(Error::new(
                ErrorKind::Other,
                "Jail is not running or jid not known",
            )),
        }
    }

    /// Remove the jail.
    ///
    /// This will kill all processes belonging to the jail, and remove any
    /// children of that jail.
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::Jail;
    ///
    /// let mut j = Jail::new("/rescue");
    /// j.start();
    /// j.kill();
    /// ```
    pub fn kill(self: &mut Jail) -> Result<(), Error> {
        match self.jid {
            Some(jid) => jail_remove(jid).and_then(|_| {
                self.jid = None;
                Ok(())
            }),
            None => Err(Error::new(
                ErrorKind::Other,
                "Jail is not running or jid not known",
            )),
        }
    }

    /// Start the jail
    ///
    /// This will call [jail_create](fn.jail_create.html) internally.
    ///
    /// Examples
    ///
    /// ```
    /// use jail::Jail;
    ///
    /// let mut j = Jail::new("/rescue");
    /// j.start();
    /// j.kill();
    /// ```
    pub fn start(self: &mut Jail) -> Result<(), Error> {
        let path = match self.path {
            None => return Err(Error::new(ErrorKind::Other, "Path not given")),
            Some(ref p) => p.clone(),
        };

        jail_create(
            &path,
            self.name.as_ref().map(String::as_str),
            self.hostname.as_ref().map(String::as_str),
        ).map(|jid| self.jid = Some(jid.clone()))
    }
}
