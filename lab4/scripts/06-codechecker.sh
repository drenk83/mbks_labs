#!/usr/bin/env sh
# Запускает CodeChecker со штатным набором (clangsa + clang-tidy),
# собирает clang-tidy-плагин и прогоняет своё правило на 1.0.30 и 1.1.0.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CC="$ROOT/work/venvs/codechecker/bin/CodeChecker"
RES="$ROOT/results"
JOBS=${JOBS:-4}

mkdir -p "$RES" "$ROOT/work/plugins"

if [ ! -x "$CC" ]; then
    echo "ставлю CodeChecker в work/venvs/codechecker"
    uv venv --python 3.13 "$ROOT/work/venvs/codechecker"
    uv pip install --python "$ROOT/work/venvs/codechecker/bin/python" \
        'codechecker==6.26.2'
fi

echo "== сборка clang-tidy плагина"
make -C "$ROOT/rules/clang-tidy"

echo "== .clang-tidy и аргументы загрузки"
for version in 1.0.30 1.1.0; do
    printf "Checks: '-*,lab4-msadpcm-block-size'\n" \
        > "$ROOT/work/src/libsndfile-$version/.clang-tidy"
done
printf -- "--load=%s\n" "$ROOT/work/plugins/lab4-msadpcm-tidy.so" \
    > "$ROOT/work/tidy-args.txt"

for version in 1.0.30 1.1.0; do
    build="$ROOT/work/build/normal-$version"
    echo "== compile_commands для $version"
    make -C "$build" clean >/dev/null 2>&1 || true
    cd "$build"
    "$CC" log -q -o "$ROOT/work/compile_commands-$version.json" \
        -b "make -j8 programs/sndfile-info"
done

cd "$ROOT/work/build/normal-1.0.30"
echo "== штатный набор CodeChecker, 1.0.30"
"$CC" analyze "$ROOT/work/compile_commands-1.0.30.json" \
    -o "$RES/codechecker-builtin-1.0.30" \
    --analyzers clangsa clang-tidy -j "$JOBS"
set +e
"$CC" parse "$RES/codechecker-builtin-1.0.30" \
    > "$RES/codechecker-builtin-1.0.30.txt" 2>&1
"$CC" parse -e json -o "$RES/codechecker-builtin-1.0.30.json" \
    "$RES/codechecker-builtin-1.0.30" >/dev/null 2>&1
set -e

for version in 1.0.30 1.1.0; do
    cd "$ROOT/work/build/normal-$version"
    echo "== своё правило CodeChecker, $version"
    "$CC" analyze "$ROOT/work/compile_commands-$version.json" \
        -o "$RES/codechecker-custom-$version" \
        --analyzers clang-tidy \
        --analyzer-config clang-tidy:take-config-from-directory=true \
        --analyzer-config "clang-tidy:cc-verbatim-args-file=$ROOT/work/tidy-args.txt" \
        -j "$JOBS"
    set +e
    "$CC" parse "$RES/codechecker-custom-$version" \
        > "$RES/codechecker-custom-$version.txt" 2>&1
    set -e
done

python3 "$ROOT/scripts/summarize.py"
echo "готово: $RES"
