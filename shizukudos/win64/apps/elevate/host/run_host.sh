#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Host control: compiles actual elevate client bodies with gcc and clang(+ASan/UBSan if available).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); APP=$(dirname "$HERE"); OUT=${1:-/tmp/elevate-flow-host}
mkdir -p "$OUT"
for cc in gcc clang; do
  command -v $cc >/dev/null || { echo "$cc missing"; continue; }
  extra=""; [ "$cc" = clang ] && [ "${SAN:-1}" = 1 ] && extra="-fsanitize=address,undefined -fno-omit-frame-pointer"
  $cc -std=c11 -O1 -g -fshort-wchar -Wall -Wextra -Werror $extra -I "$HERE" \
     "$HERE/test_elevate_flow.c" "$APP/secret.c" "$APP/consent.c" -o "$OUT/flow-$cc"
  "$OUT/flow-$cc"
done
