//! This is the jail crate.
//!
//! it aims to provide the features exposed by the FreeBSD Jail Library
//! [jail(3)](https://www.freebsd.org/cgi/man.cgi?query=jail&sektion=3&manpath=FreeBSD+11.1-stable)

extern crate libc;

#[macro_use]
extern crate failure;

pub mod process;

pub mod sys;

#[macro_use]
extern crate bitflags;

use std::path;

#[derive(Fail, Debug)]
pub enum JailError {
    #[fail(display = "An IO Error occurred: {:?}", _0)]
    IoError(#[cause] std::io::Error),

    #[fail(display = "jail_get syscall failed. The error message returned was: {}", _0)]
    JailGetError(String),

    #[fail(display = "jail_set syscall failed. The error message returned was: {}", _0)]
    JailSetError(String),

    #[fail(display = "invalid return code from jail_remove")]
    JailRemoveFailed,

    #[fail(display = "Path not given")]
    PathNotGiven,
}

impl JailError {
    fn from_errno() -> Self {
        JailError::IoError(std::io::Error::last_os_error())
    }
}

#[derive(Clone, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
#[cfg(target_os = "freebsd")]
pub struct StoppedJail {
    pub path: Option<path::PathBuf>,
    pub name: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Clone, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
#[cfg(target_os = "freebsd")]
pub struct RunningJail {
    /// The `jid` of the jail
    pub jid: i32,
}

#[cfg(target_os = "freebsd")]
pub enum JailState {
    Stopped(StoppedJail),
    Running(RunningJail),
}

#[cfg(target_os = "freebsd")]
impl Default for StoppedJail {
    fn default() -> StoppedJail {
        StoppedJail {
            path: None,
            name: None,
            hostname: None,
        }
    }
}

/// Represent a stopped jail including all information required to start it
#[cfg(target_os = "freebsd")]
impl StoppedJail {
    /// Create a new Jail instance given a path.
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::StoppedJail;
    ///
    /// let j = StoppedJail::new("/rescue");
    /// ```
    pub fn new<P: Into<path::PathBuf>>(path: P) -> StoppedJail {
        let mut ret: StoppedJail = Default::default();
        ret.path = Some(path.into());
        ret
    }

    /// Start the jail
    ///
    /// This will call [jail_create](fn.jail_create.html) internally.
    /// This will consume the [StoppedJail](struct.StoppedJail.html) and return
    /// a Result<[RunningJail](struct.RunningJail.html),Error>.
    ///
    /// Examples
    ///
    /// ```
    /// use jail::StoppedJail;
    ///
    /// let j = StoppedJail::new("/rescue");
    /// let mut running = j.start().unwrap();
    /// running.kill();
    /// ```
    pub fn start(self: StoppedJail) -> Result<RunningJail, JailError> {
        let path = match self.path {
            None => return Err(JailError::PathNotGiven),
            Some(ref p) => p.clone(),
        };

        sys::jail_create(
            &path,
            self.name.as_ref().map(String::as_str),
            self.hostname.as_ref().map(String::as_str),
        ).map(|jid| RunningJail::from_jid(jid))
    }
}

/// Represent a running jail.
#[cfg(target_os = "freebsd")]
impl RunningJail {
    /// Create a [RunningJail](struct.RunningJail.html) instance given a `jid`.
    ///
    /// No checks will be performed.
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::RunningJail;
    ///
    /// let j = RunningJail::from_jid(42);
    /// ```
    pub fn from_jid(jid: i32) -> RunningJail {
        RunningJail { jid: jid }
    }

    /// Create a [RunningJail](struct.RunningJail.html) given the jail `name`.
    ///
    /// The `jid` will be internally resolved using
    /// [jail_getid](fn.jail_getid.html).
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::RunningJail;
    ///
    /// let j = RunningJail::from_name("testjail");
    /// ```
    pub fn from_name(name: &str) -> Result<RunningJail, JailError> {
        sys::jail_getid(name).map(RunningJail::from_jid)
    }

    /// Return the jail's `name`.
    ///
    /// The name will be internall resolved using
    /// [jail_getname](fn.jail_getname.html).
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::RunningJail;
    ///
    /// let jail = RunningJail::from_name("testjail").unwrap();
    /// assert_eq!(jail.name().unwrap(), "testjail");
    /// ```
    pub fn name(self: &RunningJail) -> Result<String, JailError> {
        sys::jail_getname(self.jid)
    }

    /// Remove the jail.
    ///
    /// This will kill all processes belonging to the jail, and remove any
    /// children of that jail.
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::StoppedJail;
    ///
    /// let j = StoppedJail::new("/rescue");
    /// let mut running = j.start().unwrap();
    /// running.kill();
    /// ```
    pub fn kill(self: &mut RunningJail) -> Result<(), JailError> {
        sys::jail_remove(self.jid).and_then(|_| Ok(()))
    }
}
