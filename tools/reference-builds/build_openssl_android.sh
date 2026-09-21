#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 4 ]; then
  echo "usage: build_openssl_android.sh <source-dir> <out-dir> <ndk-root> <api>" >&2
  exit 2
fi

src="$(cd "$1" && pwd)"
out="$(mkdir -p "$2" && cd "$2" && pwd)"
ndk="$(cd "$3" && pwd)"
api="$4"
toolchain="$ndk/toolchains/llvm/prebuilt/linux-x86_64"

test -x "$toolchain/bin/aarch64-linux-android${api}-clang"
export ANDROID_NDK_ROOT="$ndk"
export ANDROID_NDK_HOME="$ndk"
export PATH="$toolchain/bin:$PATH"

cd "$src"
rm -f Makefile
perl ./Configure android-arm64 shared no-tests   --prefix="$out/install"   --openssldir="$out/install/ssl"   -D__ANDROID_API__="$api"

make -j2 build_libs

mkdir -p "$out/lib"
shopt -s nullglob
for f in libcrypto.so* libssl.so*; do
  if [ -f "$f" ] || [ -L "$f" ]; then
    cp -L "$f" "$out/lib/$(basename "$f")"
  fi
done

count="$(find "$out/lib" -maxdepth 1 -type f -name '*.so*' | wc -l)"
if [ "$count" -lt 2 ]; then
  echo "expected OpenSSL shared libraries, found $count" >&2
  find "$src" -maxdepth 2 -type f -name 'lib*.so*' -print >&2 || true
  exit 3
fi
