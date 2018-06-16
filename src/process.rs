//! Jail-Specific extensions to the `std::process` module

use libc;

use std::process;

use std::io::{Error, ErrorKind};
use std::os::unix::process::CommandExt;

use RunningJail;

/// Extension to the `std::process::Command` builder to run the command in a
/// jail.
///
/// Adds a `before_exec` hook to the `std::process::Command` builder that calls
/// the `jail_attach`(2) syscall.
///
/// # Examples
///
/// ```
/// # use std::process::Command;
/// use jail::process::Jailed;
///
/// # let jail = jail::StoppedJail::new("/rescue")
/// #     .name("testjail_process")
/// #     .start()
/// #     .expect("could not start jail");
/// #
/// let output = Command::new("/hostname")
///              .jail(&jail)
///              .output()
///              .expect("Failed to execute command");
///
/// println!("output: {:?}", output.stdout);
/// # jail.kill().expect("could not stop jail");
/// ```
#[cfg(target_os = "freebsd")]
pub trait Jailed {
    /// Sets the child process to be executed within a jail. This translates
    /// to calling `jail_attach` in the child process. Failure in the
    /// `jail_attach` call will cause the spawn to fail.
    fn jail(&mut self, jail: &RunningJail) -> &mut process::Command;
}

#[cfg(target_os = "freebsd")]
impl Jailed for process::Command {
    fn jail(&mut self, jail: &RunningJail) -> &mut process::Command {
        let jid = jail.jid;
        self.before_exec(move || {
            let ret = unsafe { libc::jail_attach(jid) };
            match ret {
                0 => Ok(()),
                -1 => Err(Error::last_os_error()),
                _ => Err(Error::new(
                    ErrorKind::Other,
                    "invalid return value from jail_attach",
                )),
            }
        });

        self
    }
}
