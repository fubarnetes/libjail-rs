use process::Jailed;
use rctl;
use running::RunningJail;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use stopped::StoppedJail;

#[test]
fn test_rctl_yes() {
    if !rctl::State::check().is_enabled() {
        // If we don't have RCTL, let's just skip this test.
        return;
    }

    let running = StoppedJail::new("/")
        .name("testjail_rctl_yes")
        .limit(
            rctl::Resource::Wallclock,
            rctl::Limit::amount(1),
            rctl::Action::Signal(rctl::Signal::SIGKILL),
        )
        .start()
        .expect("Could not start Jail");

    // this should hang until killed by the limit
    let output = Command::new("/usr/bin/yes")
        .jail(&running)
        .output()
        .expect("Failed to start yes command");

    assert!(output.status.code() == None);
    assert!(output.status.signal() == Some(9));

    println!("{:?}", output);

    running.stop().expect("Could not stop Jail");
}

#[test]
fn test_name_nonexistent_jail() {
    // Assume Jail 424242 is not running
    let r: RunningJail = RunningJail::from_jid_unchecked(424242);

    r.name()
        .expect_err("Could get name for jail 424242 which should not be running.");
}

#[test]
fn test_params_nonexistent_jail() {
    // Assume Jail 424242 is not running
    let r: RunningJail = RunningJail::from_jid_unchecked(424242);

    r.params()
        .expect_err("Could get name for jail 424242 which should not be running.");
}
