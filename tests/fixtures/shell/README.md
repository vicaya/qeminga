# Shell discovery fixtures

Every file here goes through `scripts/check-shell.sh`, the same as the
repository's own scripts, so CI's `shellcheck` job lints these files with
the pinned shellcheck release. The checks therefore run end to end: the
dialect the script detects is the one shellcheck applies.

- The shell scripts are clean. Each one uses a feature of its dialect, so
  linting it as the wrong shell, or failing to tell shellcheck the shell
  (SC1008), fails CI.
- The files that are not shell scripts are not valid shell. Classifying one
  of them as shell fails CI.

`tests/ci_workflow.rs` (`the_shell_fixtures_are_discovered_by_name_and_interpreter`)
pins which files are listed.
