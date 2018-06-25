//! A rust library for FreeBSD jails.
//!
//! it aims to provide the features exposed by the FreeBSD Jail Library
//! [jail(3)](https://www.freebsd.org/cgi/man.cgi?query=jail&sektion=3&manpath=FreeBSD+11.1-stable)

extern crate byteorder;

#[macro_use]
extern crate failure;

extern crate libc;

extern crate sysctl;

#[macro_use]
mod sys;

#[macro_use]
extern crate bitflags;

extern crate nix;

extern crate rctl;

use std::collections::HashMap;
use std::convert;
use std::net;
use std::path;

mod error;
pub use error::JailError;

mod running;
pub use running::RunningJail;

mod stopped;
pub use stopped::StoppedJail;

pub mod param;
pub mod process;

/// Represents a running or stopped jail.
#[cfg(target_os = "freebsd")]
pub enum Jail {
    Stopped(StoppedJail),
    Running(RunningJail),
}

impl convert::From<RunningJail> for Jail {
    fn from(running: RunningJail) -> Self {
        Jail::Running(running)
    }
}

impl convert::From<StoppedJail> for Jail {
    fn from(stopped: StoppedJail) -> Self {
        Jail::Stopped(stopped)
    }
}

impl Jail {
    /// Check if a jail is running
    pub fn is_started(&self) -> bool {
        match self {
            Jail::Running(_) => true,
            Jail::Stopped(_) => false,
        }
    }

    /// Start the Jail
    ///
    /// This calls start() on a stopped Jail, and is a no-op for an already
    /// running Jail.
    pub fn start(self) -> Result<Self, JailError> {
        match self {
            Jail::Running(r) => Ok(Jail::Running(r)),
            Jail::Stopped(s) => Ok(Jail::Running(s.start()?)),
        }
    }

    /// Stop the jail
    ///
    /// This calls stop() on a started Jail, and is a no-op for an already
    /// stopped Jail.
    pub fn stop(self) -> Result<Self, JailError> {
        match self {
            Jail::Running(r) => Ok(Jail::Stopped(r.stop()?)),
            Jail::Stopped(s) => Ok(Jail::Stopped(s)),
        }
    }

    /// Get the name of the Jail
    pub fn name(&self) -> Result<String, JailError> {
        match self {
            Jail::Running(r) => r.name(),
            Jail::Stopped(s) => s
                .name
                .clone()
                .ok_or_else(|| JailError::NoSuchParameter("name".into())),
        }
    }

    /// Get the name of the Jail
    pub fn path(&self) -> Result<path::PathBuf, JailError> {
        match self {
            Jail::Running(r) => r.path(),
            Jail::Stopped(s) => s
                .path
                .clone()
                .ok_or_else(|| JailError::NoSuchParameter("path".into())),
        }
    }

    /// Get the hostname of the Jail
    pub fn hostname(&self) -> Result<String, JailError> {
        match self {
            Jail::Running(r) => r.hostname(),
            Jail::Stopped(s) => s
                .hostname
                .clone()
                .ok_or_else(|| JailError::NoSuchParameter("hostname".into())),
        }
    }

    /// Get the IP Addresses of a jail
    pub fn ips(&self) -> Result<Vec<net::IpAddr>, JailError> {
        match self {
            Jail::Running(r) => r.ips(),
            Jail::Stopped(s) => Ok(s.ips.clone()),
        }
    }

    /// Get a jail parameter
    pub fn param(&self, name: &str) -> Result<param::Value, JailError> {
        match self {
            Jail::Running(r) => r.param(name),
            Jail::Stopped(s) => s
                .params
                .get(name)
                .ok_or_else(|| JailError::NoSuchParameter(name.into()))
                .map(|x| x.clone()),
        }
    }

    pub fn params(&self) -> Result<HashMap<String, param::Value>, JailError> {
        match self {
            Jail::Running(r) => r.params(),
            Jail::Stopped(s) => Ok(s.params.clone()),
        }
    }
}
