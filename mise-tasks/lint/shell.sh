#!/usr/bin/env bash
#MISE description="Shell scripts (shellcheck)"
#MISE tools = { "aqua:koalaman/shellcheck" = "0.11.0" }
# With files as arguments, it picks the shell scripts out of those.
# It takes file paths only, so an argument that starts with - is an error.
# Set shellcheck options in .shellcheckrc.
# With none, it takes every tracked file.
#
# A shell script is a regular file that ends in .sh or .bash, or starts with a
# sh or bash shebang. A deleted file or a link is skipped.
#
# The generated paths in the command below are skipped too, as git globs.
# -x lets shellcheck follow the files a script sources.
set -euo pipefail
ws='[[:space:]]'
shebang="^#!${ws}*(/usr/bin/env${ws}+(-S${ws}+)?|/(usr/)?(local/)?bin/)(ba)?sh(${ws}|\$)"
# Reads names that each end in a zero byte, and prints the shell scripts.
# Only the first 128 characters of a file with another extension are read.
scripts() {
  while IFS= read -r -d '' file; do
    if [ ! -f "$file" ] || [ -L "$file" ]; then continue; fi
    case $file in
      *.sh | *.bash) printf '%s\0' "$file" ;;
      *)
        first=
        { IFS= read -r -n 128 first; } 2>/dev/null <"$file" || true
        if [[ $first =~ $shebang ]]; then printf '%s\0' "$file"; fi
        ;;
    esac
  done
}
if [ "$#" -gt 0 ]; then
  for arg in "$@"; do
    case $arg in
      -*)
        echo "lint:shell takes file paths; set shellcheck options in .shellcheckrc" >&2
        exit 2
        ;;
    esac
  done
  printf '%s\0' "$@" | scripts | xargs -0 -r shellcheck -x
else
  git ls-files -z -- \
    ':(exclude,glob).build/**' \
    ':(exclude,glob)CHANGELOG.md' |
    scripts | xargs -0 -r shellcheck -x
fi
