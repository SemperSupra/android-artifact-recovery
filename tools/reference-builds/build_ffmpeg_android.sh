#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 4 ]; then
  echo "usage: build_ffmpeg_android.sh <source-dir> <out-dir> <ndk-root> <api>" >&2
  exit 2
fi

src="$(cd "$1" && pwd)"
out="$(mkdir -p "$2" && cd "$2" && pwd)"
ndk="$(cd "$3" && pwd)"
api="$4"
toolchain="$ndk/toolchains/llvm/prebuilt/linux-x86_64"
cc="$toolchain/bin/aarch64-linux-android${api}-clang"
cxx="$toolchain/bin/aarch64-linux-android${api}-clang++"

test -x "$cc"
cd "$src"

./configure   --prefix="$out/install"   --target-os=android   --arch=aarch64   --cpu=armv8-a   --enable-cross-compile   --cc="$cc"   --cxx="$cxx"   --ar="$toolchain/bin/llvm-ar"   --nm="$toolchain/bin/llvm-nm"   --ranlib="$toolchain/bin/llvm-ranlib"   --strip="$toolchain/bin/llvm-strip"   --sysroot="$toolchain/sysroot"   --enable-shared   --disable-static   --disable-programs   --disable-doc   --disable-avdevice   --disable-debug

make -j2
make install-libs

mkdir -p "$out/lib"
shopt -s nullglob
for f in "$out/install/lib"/libavcodec.so*          "$out/install/lib"/libavfilter.so*          "$out/install/lib"/libavformat.so*          "$out/install/lib"/libavutil.so*          "$out/install/lib"/libswresample.so*          "$out/install/lib"/libswscale.so*; do
  if [ -f "$f" ] || [ -L "$f" ]; then
    cp -L "$f" "$out/lib/$(basename "$f")"
  fi
done

count="$(find "$out/lib" -maxdepth 1 -type f -name '*.so*' | wc -l)"
if [ "$count" -lt 6 ]; then
  echo "expected FFmpeg shared-library family, found $count" >&2
  find "$out/install/lib" -maxdepth 1 -type f -name '*.so*' -print >&2 || true
  exit 3
fi
