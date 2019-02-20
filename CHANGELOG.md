# Changelog

## [Unreleased] - ReleaseDate

### Added

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
