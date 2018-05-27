extern crate jail;
use jail::param;
use std::path::Path;

fn main() {
    let jid = jail::sys::jail_create(Path::new("/tmp"), Some("example_param"), None)
        .expect("could not start jail");

    let hostuuid = match jail::param::get(jid, "host.hostuuid").expect("could not get hostuuid") {
        param::Value::String(s) => s,
        _ => panic!("hostuuid is not a string"),
    };

    println!("{:?}", hostuuid);

    jail::sys::jail_remove(jid).expect("could not remove jail");
}
