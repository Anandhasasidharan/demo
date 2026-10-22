#!/usr/bin/env bash
# CVE-2022-40674 case study — Linux / macOS (AddressSanitizer)
# Builds libexpat 2.4.8 (vulnerable), 2.4.8 + patch, and 2.4.9 (fixed),
# then runs the same trigger through each and compares.
set -euo pipefail
cd "$(dirname "$0")"

CC="${CC:-cc}"
command -v "$CC" >/dev/null || { echo "$CC not found"; exit 1; }

if [ ! -d src/.git ]; then
  echo "cloning libexpat..."
  git clone --quiet https://github.com/libexpat/libexpat.git src
fi
git -C src fetch --tags --quiet 2>/dev/null || true

extract() { # tag dir
  rm -rf "$2"; mkdir -p "$2"
  git -C src archive "$1" expat/lib | tar -x -C "$2"
}

build() { # dir exe
  "$CC" -DXML_STATIC -I . -I "$1/expat/lib" -O1 -g \
        -fsanitize=address -fno-omit-frame-pointer \
        -o "$2" driver.c "$1/expat/lib/xmlparse.c" "$1/expat/lib/xmltok.c" "$1/expat/lib/xmlrole.c"
}

echo "extracting sources..."
extract R_2_4_8 vuln
extract R_2_4_9 fixed
extract R_2_4_8 patched

( cd patched && patch -p1 --silent < ../patch.diff )

echo "building..."
build vuln    ap_vuln
build patched ap_patched
build fixed   ap_fixed

run() { # label exe
  echo
  echo "=== $1 ==="
  set +e
  "./$2" 2>&1 | sed 's/^/  /'
  local code=${PIPESTATUS[0]}
  set -e
  if [ "$code" -eq 0 ]; then
    printf '  -> %s\n' "no fault (exit 0)"
  else
    printf '  -> %s\n' "fault (exit $code)"
  fi
}

run "libexpat 2.4.8 (vulnerable)" ap_vuln
run "2.4.8 + patch.diff"         ap_patched
run "libexpat 2.4.9 (fixed)"     ap_fixed

cat <<'EOF'

summary
  vulnerable : ASan reports heap-use-after-free, non-zero exit
  + patch    : clean exit
  fixed 2.4.9: clean exit
EOF
