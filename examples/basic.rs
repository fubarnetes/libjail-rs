extern crate jail;

use std::process::Command;

use jail::param;
use jail::process::Jailed;

fn main() {
    let mut stopped = jail::StoppedJail::new("/rescue")
        .name("example_basic")
        .param("allow.raw_sockets", param::Value::Int(1))
        .param("allow.sysvipc", param::Value::Int(1));

    stopped.hostname = Some("testjail.example.org".to_string());

    let mut running = stopped.start().expect("Failed to start jail");

    println!("created new jail with JID {}", running.jid);

    println!(
        "the jail's jailname is '{}'",
        running.name().expect("could not get name")
    );

    println!("Let's run a command in the jail!");
    let output = Command::new("/hostname")
        .jail(&running.jid)
        .output()
        .expect("Failed to execute command in jail");

    println!("output: {}", String::from_utf8_lossy(&output.stdout));

    running.kill().expect("Failed to stop Jail");
}
