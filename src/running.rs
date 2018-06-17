use param;
use sys;
use JailError;

use std::net;
use std::path;

/// Represents a running jail.
#[derive(Clone, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
#[cfg(target_os = "freebsd")]
pub struct RunningJail {
    /// The `jid` of the jail
    pub jid: i32,
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
        self.param("name")?.unpack_string()
    }

    /// Return the jail's `path`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// # use std::path::PathBuf;
    /// #
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_path")
    /// #     .start()
    /// #     .expect("Could not start jail");
    /// let path = running.path()
    ///     .expect("Could not get path");
    /// # let expected : PathBuf = "/rescue".into();
    /// # assert_eq!(path, expected);
    /// #
    /// # running.kill();
    /// ```
    pub fn path(self: &RunningJail) -> Result<path::PathBuf, JailError> {
        Ok(self.param("path")?.unpack_string()?.into())
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
    /// #     .hostname("testjail.example.com")
    /// #     .start()
    /// #     .expect("Could not start jail");
    /// assert_eq!(running.hostname().unwrap(), "testjail.example.com");
    /// #
    /// # running.kill();
    /// ```
    pub fn hostname(self: &RunningJail) -> Result<String, JailError> {
        self.param("host.hostname")?.unpack_string()
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
                .unpack_ipv4()?
                .iter()
                .cloned()
                .map(net::IpAddr::V4),
        );
        ips.extend(
            self.param("ip6.addr")?
                .unpack_ipv6()?
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
