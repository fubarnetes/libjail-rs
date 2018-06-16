#![feature(test)]
extern crate test;

extern crate jail;

use jail::process::Jailed;
use jail::StoppedJail;
use std::process::Command;
use test::Bencher;

#[bench]
fn start_stop_jail(b: &mut Bencher) {
    b.iter(|| {
        let running = StoppedJail::new("/rescue").start().unwrap();
        running.kill().unwrap();
    });
}

#[bench]
fn start_stop_ipv4jail(b: &mut Bencher) {
    b.iter(|| {
        let running = StoppedJail::new("/rescue")
            .ip("127.0.1.1".parse().unwrap())
            .start()
            .unwrap();
        running.kill().unwrap();
    })
}

#[bench]
fn start_stop_ipv6jail(b: &mut Bencher) {
    b.iter(|| {
        let running = StoppedJail::new("/rescue")
            .ip("fe80::2".parse().unwrap())
            .start()
            .unwrap();
        running.kill().unwrap();
    })
}

#[bench]
fn start_stop_ipjail(b: &mut Bencher) {
    b.iter(|| {
        let running = StoppedJail::new("/rescue")
            .ip("127.0.1.1".parse().unwrap())
            .ip("fe80::2".parse().unwrap())
            .start()
            .unwrap();
        running.kill().unwrap();
    })
}

#[bench]
fn start_echo_helloworld_stop(b: &mut Bencher) {
    b.iter(|| {
        let running = StoppedJail::new("/rescue").start().unwrap();

        Command::new("/echo")
            .arg("hello world")
            .jail(&running.jid)
            .output()
            .unwrap();

        running.kill().unwrap();
    });
}
