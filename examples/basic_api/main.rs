extern crate jail;

use std::path::Path;

use jail::jail_getid;
use jail::process::Jailed;
use std::process::Command;

fn main() {
    let jid = jail::jail_create(
        Path::new("/rescue"),
        Some("testjailname"),
        Some("testjail.example.org"),
    ).expect("could not start jail");

    println!("created new jail with JID {}", jid);

    let jailname = jail::jail_getname(jid).expect("could not get jail name");
    println!("the jail's jailname is '{}'", jailname);

    println!("Let's run a command in the jail!");
    let output = Command::new("/hostname")
        .jail(jid)
        .output()
        .expect("Failed to execute command in jail");

    println!("output: {}", String::from_utf8_lossy(&output.stdout));

    jail::jail_remove(jid).expect("could not kill jail");
}
