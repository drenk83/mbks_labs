#!/usr/bin/env sh
# Скачивает исходники libsndfile 1.0.30 (уязвимая) и 1.1.0 (исправленная)
# в work/src. Каталог work/ в git не входит.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SRC="$ROOT/work/src"
mkdir -p "$SRC"

fetch() {
    tag=$1
    dir=$2
    if [ -d "$SRC/$dir/.git" ]; then
        echo "уже есть: $dir"
    else
        echo "клонирую $tag -> $dir"
        git clone --depth 1 --branch "$tag" \
            https://github.com/libsndfile/libsndfile.git "$SRC/$dir"
    fi
    (cd "$SRC/$dir" && autoreconf -i -f > autoreconf.log 2>&1)
    echo "autoreconf: $dir"
}

fetch v1.0.30 libsndfile-1.0.30
fetch 1.1.0 libsndfile-1.1.0
