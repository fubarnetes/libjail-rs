extern crate jail;

use std::path::Path;

use jail::param;
use jail::process::Jailed;
use std::process::Command;

fn main() {
    let jid = jail::sys::jail_create(
        Path::new("/rescue"),
        Some("testjailname"),
        Some("testjail.example.org"),
    ).expect("could not start jail");
    println!("created new jail with JID {}", jid);

    let ip4s = param::Value::Ipv4Addrs(vec![
        "127.0.1.1".parse().unwrap(),
        "10.20.30.40".parse().unwrap(),
    ]);

    let ip6s = param::Value::Ipv6Addrs(vec![
        "fe80::2".parse().unwrap(),
        "fe80::3".parse().unwrap(),
        "fe80::4".parse().unwrap(),
    ]);

    param::set(jid, "ip4.addr", ip4s).expect("could not set IPv4 addresses");
    param::set(jid, "ip6.addr", ip6s).expect("could not set IPv6 addresses");

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

    let ip4 = jail::param::get(jid, "ip4.addr");
    println!("ip4: {:?}", ip4);

    let ip6 = jail::param::get(jid, "ip6.addr");
    println!("ip6: {:?}", ip6);

    jail::sys::jail_remove(jid).expect("could not kill jail");
}
