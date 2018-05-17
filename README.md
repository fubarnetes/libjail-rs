# libjail-rs

libjail-rs aims to be a rust implementation of the FreeBSD [jail(3)](https://www.freebsd.org/cgi/man.cgi?query=jail&sektion=3&manpath=FreeBSD+11.1-stable) library. While feature parity is a goal, a one-to-one implementation of all functions in [jail(3)](https://www.freebsd.org/cgi/man.cgi?query=jail&sektion=3&manpath=FreeBSD+11.1-stable) is not.

# Project status

This library is still under heavy development

# Usage

Execute a command in a jail:
```rust
use std::process::Command;
use jail::jail_getid;
use jail::process::Jailed;

let output = Command::new("hostname")
             .jail(jail_getid("testjail").unwrap())
             .output()
             .expect("Failed to execute command");

println!("output: {:?}", output.stdout); 
```
