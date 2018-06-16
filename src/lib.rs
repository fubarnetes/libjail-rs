//! This is the jail crate.
//!
//! it aims to provide the features exposed by the FreeBSD Jail Library
//! [jail(3)](https://www.freebsd.org/cgi/man.cgi?query=jail&sektion=3&manpath=FreeBSD+11.1-stable)

extern crate byteorder;

#[macro_use]
extern crate failure;

extern crate libc;

extern crate sysctl;

pub mod process;

#[macro_use]
mod sys;

pub mod param;

#[macro_use]
extern crate bitflags;

extern crate nix;

use std::collections::HashMap;
use std::net;
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

    #[fail(display = "No such parameter: {}", _0)]
    NoSuchParameter(String),

    #[fail(display = "Could not parameter type: {:?}", _0)]
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
    fn from_errno() -> Self {
        JailError::IoError(std::io::Error::last_os_error())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg(target_os = "freebsd")]
pub struct StoppedJail {
    pub path: Option<path::PathBuf>,
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub params: HashMap<String, param::Value>,
    pub ips: Vec<std::net::IpAddr>,
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
            params: HashMap::new(),
            ips: vec![],
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
    /// let stopped = StoppedJail::new("/rescue");
    /// let running = stopped.start().unwrap();
    /// # running.kill();
    /// ```
    pub fn start(self: StoppedJail) -> Result<RunningJail, JailError> {
        let path = match self.path {
            None => return Err(JailError::PathNotGiven),
            Some(ref p) => p.clone(),
        };

        let ret = sys::jail_create(
            &path,
            self.name.as_ref().map(String::as_str),
            self.hostname.as_ref().map(String::as_str),
        ).map(RunningJail::from_jid)?;

        // Set the IP Addresses
        let ip4s = param::Value::Ipv4Addrs(
            self.ips
                .iter()
                .filter(|ip| ip.is_ipv4())
                .map(|ip| match ip {
                    std::net::IpAddr::V4(ip4) => *ip4,
                    _ => panic!("unreachable"),
                })
                .collect(),
        );

        let ip6s = param::Value::Ipv6Addrs(
            self.ips
                .iter()
                .filter(|ip| ip.is_ipv6())
                .map(|ip| match ip {
                    std::net::IpAddr::V6(ip6) => *ip6,
                    _ => panic!("unreachable"),
                })
                .collect(),
        );

        param::set(ret.jid, "ip4.addr", ip4s)?;
        param::set(ret.jid, "ip6.addr", ip6s)?;

        // Set remaining parameters
        for (param, value) in self.params {
            param::set(ret.jid, &param, value)?;
        }

        Ok(ret)
    }

    /// Set the jail name
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// #
    /// let mut stopped = StoppedJail::new("/rescue")
    ///     .name("test_stopped_name");
    ///
    /// assert_eq!(stopped.name, Some("test_stopped_name".to_string()));
    /// ```
    pub fn name<S: Into<String>>(mut self: Self, name: S) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set a jail parameter
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// #
    /// use jail::param;
    ///
    /// let mut stopped = StoppedJail::new("/rescue")
    ///     .param("allow.raw_sockets", param::Value::Int(1));
    /// ```
    pub fn param<S: Into<String>>(mut self: Self, param: S, value: param::Value) -> Self {
        self.params.insert(param.into(), value);
        self
    }

    /// Add an IP Address
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// # use std::net::IpAddr;
    /// #
    /// let mut stopped = StoppedJail::new("rescue")
    ///     .ip("127.0.1.1".parse().expect("could not parse 127.0.1.1"))
    ///     .ip("fe80::2".parse().expect("could not parse ::1"));
    /// ```
    pub fn ip(mut self: Self, ip: std::net::IpAddr) -> Self {
        self.ips.push(ip);
        self
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
    /// # use jail::StoppedJail;
    /// # let jail = StoppedJail::new("/rescue")
    /// #     .name("testjail_from_jid")
    /// #     .start()
    /// #     .expect("could not start jail");
    /// # let jid = jail.jid;
    ///
    /// let running = RunningJail::from_jid(jid);
    /// # running.kill();
    /// ```
    pub fn from_jid(jid: i32) -> RunningJail {
        RunningJail { jid }
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
    /// # use jail::StoppedJail;
    /// # let jail = StoppedJail::new("/rescue")
    /// #     .name("testjail_from_name")
    /// #     .start()
    /// #     .expect("could not start jail");
    ///
    /// let running = RunningJail::from_name("testjail_from_name")
    ///     .expect("Could not get testjail");
    /// #
    /// # running.kill();
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
    /// # use jail::StoppedJail;
    /// #
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_name")
    /// #     .start()
    /// #     .expect("Could not start jail");
    /// assert_eq!(running.name().unwrap(), "testjail_name");
    /// #
    /// # running.kill();
    /// ```
    pub fn name(self: &RunningJail) -> Result<String, JailError> {
        sys::jail_getname(self.jid)
    }

    /// Get the IP addresses
    ///
    /// # Examples
    /// ```
    /// # use jail::StoppedJail;
    /// # use std::net::IpAddr;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_ip")
    /// #     .ip("127.0.1.2".parse().unwrap())
    /// #     .ip("fe80::2".parse().unwrap())
    /// #     .start()
    /// #     .expect("Could not start jail");
    /// let ips = running.ips()
    ///     .expect("could not get ip addresses");
    /// assert_eq!(ips[0], "127.0.1.2".parse::<IpAddr>().unwrap());
    /// assert_eq!(ips[1], "fe80::2".parse::<IpAddr>().unwrap());
    /// # running.kill();
    /// ```
    pub fn ips(self: &RunningJail) -> Result<Vec<net::IpAddr>, JailError> {
        let mut ips: Vec<net::IpAddr> = vec![];
        ips.extend(
            self.param("ip4.addr")?
                .into_ipv4()?
                .iter()
                .cloned()
                .map(net::IpAddr::V4),
        );
        ips.extend(
            self.param("ip6.addr")?
                .into_ipv6()?
                .iter()
                .cloned()
                .map(net::IpAddr::V6),
        );
        Ok(ips)
    }

    /// Return a jail parameter.
    ///
    /// # Examples
    /// ```
    /// # use jail::StoppedJail;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .start().unwrap();
    /// #
    /// let hostuuid = running.param("host.hostuuid")
    ///     .expect("could not get jail hostuuid");
    /// #
    /// # println!("jail uuid: {:?}", hostuuid);
    /// # running.kill();
    /// ```
    pub fn param(self: &Self, name: &str) -> Result<param::Value, JailError> {
        param::get(self.jid, name)
    }

    /// Set a jail parameter.
    ///
    /// # Examples
    /// ```
    /// # use jail::StoppedJail;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .start().unwrap();
    /// #
    /// use jail::param;
    /// running.param_set("allow.raw_sockets", param::Value::Int(1))
    ///     .expect("could not set parameter");
    /// # let readback = running.param("allow.raw_sockets")
    /// #   .expect("could not read back value");
    /// # assert_eq!(readback, param::Value::Int(1));
    /// # running.kill();
    /// ```
    pub fn param_set(self: &Self, name: &str, value: param::Value) -> Result<(), JailError> {
        param::set(self.jid, name, value)
    }

    /// Kill a running jail, consuming it.
    ///
    /// This will kill all processes belonging to the jail, and remove any
    /// children of that jail.
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .start().unwrap();
    /// running.kill();
    /// ```
    pub fn kill(self: RunningJail) -> Result<(), JailError> {
        sys::jail_remove(self.jid).and_then(|_| Ok(()))
    }
}
