fn main() {
    if cfg!(not(target_os = "freebsd")) {
        panic!("this crate provides FreeBSD-specific bindings and is therefore only available on FreeBSD");
    }
}
