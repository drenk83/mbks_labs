#!/usr/bin/env sh
# Генерирует PoC и прогоняет его на уязвимой (1.0.30) и исправленной (1.1.0)
# сборках с AddressSanitizer.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
POC="$ROOT/poc/msadpcm_poc.wav"
RES="$ROOT/results"

mkdir -p "$RES"
python3 "$ROOT/poc/gen_msadpcm_poc.py" -o "$POC"

run() {
    version=$1
    log="$RES/poc-$version-asan.log"
    set +e
    ASAN_OPTIONS=detect_leaks=0 \
        "$ROOT/work/build/asan-$version/programs/sndfile-info" "$POC" \
        > "$log" 2>&1
    rc=$?
    set -e
    echo "== libsndfile $version, ASan: код возврата $rc, лог $log"
    grep -E "ERROR: AddressSanitizer|WRITE of size|SUMMARY: AddressSanitizer|samplesperblock" \
        "$log" | head -6 || true
}

run 1.0.30
run 1.1.0
