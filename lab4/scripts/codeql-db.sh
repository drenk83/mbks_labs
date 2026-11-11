#!/usr/bin/env sh
# Создаёт базы CodeQL для libsndfile 1.0.30 и 1.1.0.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

for version in 1.0.30 1.1.0; do
    make -C "$ROOT/work/build/normal-$version" clean >/dev/null 2>&1
    "$ROOT/work/tools/codeql/codeql" database create "$ROOT/work/db-$version" \
        --language=cpp \
        --source-root="$ROOT/work/src/libsndfile-$version" \
        --command="make -C $ROOT/work/build/normal-$version programs/sndfile-info" \
        --overwrite
done
