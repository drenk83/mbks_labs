#!/usr/bin/env sh
# Сборка libsndfile для CodeQL: CodeQL запускает команду из --source-root,
# поэтому скрипт сам переходит в нужный каталог сборки.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=${1:?укажите версию: 1.0.30 или 1.1.0}
build_dir="$root/work/build/normal-$version"
cd "$build_dir"
exec make -j"${JOBS:-4}" programs/sndfile-info
