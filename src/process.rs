use libc;

use std::process;

use std::io::{Error, ErrorKind};
use std::os::unix::process::CommandExt;

#[cfg(target_os = "freebsd")]
pub trait Jailed {
    /// Sets the child process to be executed within a jail. This translates
    /// to calling `jail_attach` in the child process. Failure in the
    /// `jail_attach` call will cause the spawn to fail.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::process::Command;
    /// use jail::process::Jailed;
    /// # use std::path::Path;
    ///
    /// # let jid = jail::sys::jail_create(Path::new("/rescue"), Some("testjail_process"), None)
    /// #     .expect("could not start jail");
    /// #
    /// let output = Command::new("/hostname")
    ///              .jail(&jid)
    ///              .output()
    ///              .expect("Failed to execute command");
    ///
    /// println!("output: {:?}", output.stdout);
    /// # jail::sys::jail_remove(jid);
    /// ```
    fn jail(&mut self, jid: &i32) -> &mut process::Command;
}

/// FreeBSD-Jail specifc extensions to the `std::process::Command` builder
#[cfg(target_os = "freebsd")]
impl Jailed for process::Command {
    fn jail(&mut self, jid: &i32) -> &mut process::Command {
        let jid = jid.clone();
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
