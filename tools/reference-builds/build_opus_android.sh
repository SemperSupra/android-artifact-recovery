#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 4 ]; then
  echo "usage: build_opus_android.sh <source-dir> <out-dir> <ndk-root> <api>" >&2
  exit 2
fi

src="$(cd "$1" && pwd)"
out="$(mkdir -p "$2" && cd "$2" && pwd)"
ndk="$(cd "$3" && pwd)"
api="$4"
toolchain="$ndk/toolchains/llvm/prebuilt/linux-x86_64"

export CC="$toolchain/bin/aarch64-linux-android${api}-clang"
export CXX="$toolchain/bin/aarch64-linux-android${api}-clang++"
export AR="$toolchain/bin/llvm-ar"
export RANLIB="$toolchain/bin/llvm-ranlib"
export NM="$toolchain/bin/llvm-nm"
export STRIP="$toolchain/bin/llvm-strip"

cd "$src"
./autogen.sh
./configure   --host=aarch64-linux-android   --prefix="$out/install"   --disable-static   --enable-shared   --disable-doc   --disable-extra-programs

make -j2
make install

mkdir -p "$out/lib"
shopt -s nullglob
for f in "$out/install/lib"/libopus.so*; do
  if [ -f "$f" ] || [ -L "$f" ]; then
    cp -L "$f" "$out/lib/$(basename "$f")"
  fi
done

count="$(find "$out/lib" -maxdepth 1 -type f -name 'libopus.so*' | wc -l)"
if [ "$count" -lt 1 ]; then
  echo "expected libopus shared library" >&2
  exit 3
fi
