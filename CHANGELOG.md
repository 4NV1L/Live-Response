# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Ongoing improvements and bug fixes.
- Stress testing on Linux host 
- Testing out summary functionality with both root and non-root privileges etc. 

## [1.2.0] - 2025-12-05
### Added
- Detailed README with organized command list and usage examples.
- Summary reporting at the end of script execution (actions, failures, duration).
- Efficient hidden file and hash search (limited to key directories).
- Full scan now includes all light scan steps.
- Error handling for unsupported or missing commands.

### Changed
- Improved script formatting and indentation for readability.
- Updated output file structure and logging.

### Fixed
- Performance issues with recursive `find` and `ls` commands on large directories.

## [1.1.0] - 2025-11-20
### Added
- Light scan mode for quick triage.
- Docker awareness and cryptominer checks.

### Changed
- Output files now timestamped and organized by hostname.

## [1.0.0] - 2020-04-06
### Added
- Initial release: comprehensive Linux forensic collection script.
- Collects user, process, network, file, and log data.
- Saves all output to `/tmp/Forensics/Incident` and `/tmp/Forensics/Backuplogs`.
