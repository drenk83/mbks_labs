#!/usr/bin/env sh
# Собирает libsndfile 1.0.30 и 1.1.0 в обычном варианте и с AddressSanitizer.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
JOBS=${JOBS:-8}

for version in 1.0.30 1.1.0; do
    for mode in normal asan; do
        build="$ROOT/work/build/$mode-$version"
        src="$ROOT/work/src/libsndfile-$version"
        mkdir -p "$build"
        cd "$build"

        if [ "$mode" = asan ]; then
            CFLAGS="-std=gnu11 -fsanitize=address -g -O1"
            LDFLAGS="-fsanitize=address"
        else
            CFLAGS="-std=gnu11 -g -O1"
            LDFLAGS=""
        fi

        echo "== $mode-$version: configure"
        CC=clang CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" \
            "$src/configure" --disable-external-libs \
            --disable-shared --enable-static > configure.log 2>&1
        echo "== $mode-$version: make"
        make -j"$JOBS" programs/sndfile-info > make.log 2>&1
        echo "готово: $build/programs/sndfile-info"
    done
done

echo
echo "Проверка версий:"
"$ROOT/work/build/normal-1.0.30/programs/sndfile-info" --version 2>&1 | head -3 || true
"$ROOT/work/build/normal-1.1.0/programs/sndfile-info" --version 2>&1 | head -3 || true
