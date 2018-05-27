extern crate jail;

use std::path::Path;

use jail::process::Jailed;
use std::process::Command;

fn main() {
    let jid = jail::sys::jail_create(
        Path::new("/rescue"),
        Some("testjailname"),
        Some("testjail.example.org"),
    ).expect("could not start jail");

    println!("created new jail with JID {}", jid);

    let jailname = jail::sys::jail_getname(jid).expect("could not get jail name");
    println!("the jail's jailname is '{}'", jailname);

    println!("Let's run a command in the jail!");
    let output = Command::new("/hostname")
        .jail(&jid)
        .output()
        .expect("Failed to execute command in jail");

    println!("output: {}", String::from_utf8_lossy(&output.stdout));

    let param = jail::param::get(jid, "host.hostuuid");
    println!("param: {:?}", param);

    jail::sys::jail_remove(jid).expect("could not kill jail");
}
