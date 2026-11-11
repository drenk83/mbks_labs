#!/usr/bin/env sh
# Генерирует PoC и прогоняет его на 1.0.30 и 1.1.0 под ASan.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
POC="$ROOT/poc/msadpcm_poc.wav"
RES="$ROOT/results"

python3 "$ROOT/poc/gen_msadpcm_poc.py" -o "$POC"

for version in 1.0.30 1.1.0; do
    log="$RES/poc-$version-asan.log"
    ASAN_OPTIONS=detect_leaks=0 \
        "$ROOT/work/build/asan-$version/programs/sndfile-info" "$POC" \
        > "$log" 2>&1
    rc=$?
    echo "== libsndfile $version, ASan: код возврата $rc, лог $log"
    grep -E "ERROR: AddressSanitizer|WRITE of size|SUMMARY: AddressSanitizer|samplesperblock" "$log" | head -6
done
