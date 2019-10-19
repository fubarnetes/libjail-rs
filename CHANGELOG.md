# Changelog

## [Unreleased] - ReleaseDate

## [0.1.1] - 2019-10-19

### Changed

* Updated `sysctl` to version 0.4.0
* Updated `strum` to 0.16.0
* Use `pre_exec` instead of `before_exec` in `Jailed::jail`

### Bugfixes

* Remove the need to set an increased `type_length_limit` (Thanks to @phyber!)

## [0.1.0] - 2019-06-07

### Known Issues
* Due to an issue with `type_length_limit` increasing exponentially,
  consumers of libjail-rs may have to set an increased `type_length_limit`
  on their crate.
  ([#59](https://github.com/fubarnetes/libjail-rs/issues/59))

### Added

* implementations for `TryFrom` to start / stop jails.
* example showing how to query RCTL usage.
* code coverage with codecov.io. Unfortunately, this doesn't yet take docstests
  into account, so coverage is actually a bit better in reality.
* serialization support for stopped jails with serde (#53)

### Changed

* Published `RunningJails` as `RunningJailIter`
* `RunningJail::from_jid(...)` now returns an `Option<RunningJail>` depending on
  whether a Jail exists with that JID. The old behaviour of
  `RunningJail::from_jid(...)` can be found in
  `RunningJail::from_jid_unchecked(...)`
* Added debug logging using the `log` crate.

### Bugfixes
* Increased `type_length_limit` to 17825821 to fix a build failure on
  Rust 1.35.0 (See #59, #60, https://github.com/rust-lang/rust/issues/58952).
* `RunningJails::params()` now correctly fails when an error occurs while
  reading parameters.

## [0.0.6] - 2018-12-25

### Added
* support for setting tunable jail parameters
* support for non-persistent jails

### Changed
* examples/jls: fixed `nix` version mismatch with `rctl` crate
* fixed jail teardown and save if RCTL not enabled
* `RunningJail` now derives `Copy`.
* `RunningJail::jail_attach` is now public.
* `RunningJail::save` now no longer saves the `vnet` parameter if it is set to
  `inherit` (2). See #34.
* updated rctl to 0.0.5
* updated prettytable-rs to 0.8.0

## [0.0.5] - 2018-07-05

### Added
* RCTL / RACCT support

## [0.0.4] - 2018-06-21

### Added
* this Changelog

* iteration over running jails
* `jls` example showcasing iteration
* API to query parameter types
