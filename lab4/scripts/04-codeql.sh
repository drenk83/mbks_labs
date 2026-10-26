#!/usr/bin/env sh
# Создаёт базы CodeQL, запускает пять штатных CWE-запросов и своё правило.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TOOLS="$ROOT/work/tools"
CODEQL_HOME="$TOOLS/codeql"
CODEQL="$CODEQL_HOME/codeql"
RES="$ROOT/results"
JOBS=${JOBS:-4}

mkdir -p "$TOOLS" "$RES"

if [ ! -x "$CODEQL" ]; then
    echo "CodeQL не найден, скачиваю bundle 2.27.3 (около 560 МБ)"
    curl -L --fail --retry 3 \
        -o "$TOOLS/codeql-bundle.tar.zst" \
        "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.3/codeql-bundle-linux64.tar.zst"
    rm -rf "$CODEQL_HOME"
    mkdir -p "$CODEQL_HOME"
    tar --zstd -xf "$TOOLS/codeql-bundle.tar.zst" -C "$CODEQL_HOME" --strip-components=1
fi

CPP_QUERIES=$(find "$CODEQL_HOME/qlpacks/codeql/cpp-queries" \
    -mindepth 1 -maxdepth 1 -type d | sort -V | tail -1)
if [ -z "$CPP_QUERIES" ]; then
    echo "не найден пакет codeql/cpp-queries" >&2
    exit 1
fi

echo "CodeQL: $("$CODEQL" version | head -1)"
echo "cpp-queries: $CPP_QUERIES"

for version in 1.0.30 1.1.0; do
    echo "== база $version"
    make -C "$ROOT/work/build/normal-$version" clean >/dev/null 2>&1 || true
    "$CODEQL" database create "$ROOT/work/db-$version" \
        --language=cpp \
        --source-root="$ROOT/work/src/libsndfile-$version" \
        --command="$ROOT/scripts/codeql-build.sh $version" \
        --overwrite
done

echo "== пять штатных запросов"
"$CODEQL" database analyze "$ROOT/work/db-1.0.30" \
    "$CPP_QUERIES/Security/CWE/CWE-120/UnboundedWrite.ql" \
    "$CPP_QUERIES/Security/CWE/CWE-190/IntegerOverflowTainted.ql" \
    "$CPP_QUERIES/Security/CWE/CWE-129/ImproperArrayIndexValidation.ql" \
    "$CPP_QUERIES/Security/CWE/CWE-457/ConditionallyUninitializedVariable.ql" \
    "$CPP_QUERIES/Security/CWE/CWE-468/SuspiciousAddWithSizeof.ql" \
    --format=sarif-latest \
    --output="$RES/codeql-cwe-1.0.30.sarif" \
    --threads="$JOBS"

echo "== своё правило"
for version in 1.0.30 1.1.0; do
    "$CODEQL" database analyze "$ROOT/work/db-$version" \
        "$ROOT/rules/codeql/msadpcm-block-size.ql" \
        --format=sarif-latest \
        --output="$RES/codeql-custom-$version.sarif" \
        --threads="$JOBS"
done

python3 "$ROOT/scripts/summarize.py"
echo "готово: $RES"
