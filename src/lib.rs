//! This is the jail crate.
//!
//! it aims to provide the features exposed by the FreeBSD Jail Library
//! [jail(3)](https://www.freebsd.org/cgi/man.cgi?query=jail&sektion=3&manpath=FreeBSD+11.1-stable)

extern crate libc;

pub mod process;

pub mod sys;

use std::io::{Error, ErrorKind};

#[macro_use]
extern crate bitflags;

use std::path;

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
        sys::jail_getid(name).map(Jail::from_jid)
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
            Some(jid) => sys::jail_getname(jid),
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
            Some(jid) => sys::jail_remove(jid).and_then(|_| {
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

        sys::jail_create(
            &path,
            self.name.as_ref().map(String::as_str),
            self.hostname.as_ref().map(String::as_str),
        ).map(|jid| self.jid = Some(jid))
    }
}
