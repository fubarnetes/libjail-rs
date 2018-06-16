#![feature(test)]
extern crate test;

extern crate jail;

use jail::StoppedJail;
use test::Bencher;

#[bench]
fn get_ips(b: &mut Bencher) {
    let mut running = StoppedJail::new("/rescue")
        .ip("127.0.1.1".parse().unwrap())
        .ip("fe80::2".parse().unwrap())
        .start()
        .unwrap();
    b.iter(|| running.ips().unwrap());
    running.kill().unwrap();
}
