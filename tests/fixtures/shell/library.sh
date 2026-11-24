# shellcheck shell=bash
# A sourced library: a shell script by name, without a shebang.
greet() { local who=$1; echo "hello $who"; }
