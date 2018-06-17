use std::collections::HashMap;
use std::net;
use std::path;

use param;
use sys;
use JailError;
use RunningJail;

/// Represent a stopped jail including all information required to start it
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg(target_os = "freebsd")]
pub struct StoppedJail {
    /// The path of root file system of the jail
    pub path: Option<path::PathBuf>,

    /// The jail name
    pub name: Option<String>,

    /// The jail hostname
    pub hostname: Option<String>,

    /// A hashmap of jail parameters and their values
    pub params: HashMap<String, param::Value>,

    /// A list of IP (v4 and v6) addresses to be assigned to this jail
    pub ips: Vec<net::IpAddr>,
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
                    net::IpAddr::V4(ip4) => *ip4,
                    _ => panic!("unreachable"),
                })
                .collect(),
        );

        let ip6s = param::Value::Ipv6Addrs(
            self.ips
                .iter()
                .filter(|ip| ip.is_ipv6())
                .map(|ip| match ip {
                    net::IpAddr::V6(ip6) => *ip6,
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

    /// Set the jail name
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// #
    /// let mut stopped = StoppedJail::new("/rescue")
    /// #   .name("test_stopped_hostname")
    ///     .hostname("example.com");
    ///
    /// assert_eq!(stopped.hostname, Some("example.com".to_string()));
    /// ```
    pub fn hostname<S: Into<String>>(mut self: Self, hostname: S) -> Self {
        self.hostname = Some(hostname.into());
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
    pub fn ip(mut self: Self, ip: net::IpAddr) -> Self {
        self.ips.push(ip);
        self
    }
}
