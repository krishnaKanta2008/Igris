#!/usr/bin/env bash
# Read-only toolchain verification for Igris OS development.
# Does not use sudo and does not modify the repository.
set -u

echo "=== toolchains ==="
for t in gcc g++ make cmake ninja pkg-config rustc cargo python3 pip3 git gdb valgrind strace socat jq; do
  if c=$(command -v "$t" 2>/dev/null); then
    printf '%-14s %s\n' "$t" "$c"
  else
    printf '%-14s MISSING\n' "$t"
  fi
done

echo "=== versions ==="
gcc --version | head -1
cmake --version | head -1
rustc --version
cargo --version
python3 --version
git --version
