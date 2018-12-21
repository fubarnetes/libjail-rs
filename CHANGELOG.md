# Changelog

## [Unreleased] - ReleaseDate

### Added
* support for setting tunable jail parameters

### Changed
* examples/jls: fixed `nix` version mismatch with `rctl` crate
* fixed jail teardown and save if RCTL not enabled
* `RunningJail` now derives `Copy`.
* `RunningJail::jail_attach` is now public.
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
