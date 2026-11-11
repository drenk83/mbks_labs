#!/usr/bin/env sh

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CODEQL="$ROOT/work/tools/codeql/codeql"
QUERIES="$ROOT/work/tools/codeql/qlpacks/codeql/cpp-queries/1.9.2/Security/CWE"
RES="$ROOT/results"

echo "== пять штатных запросов"
"$CODEQL" database analyze "$ROOT/work/db-1.0.30" \
    "$QUERIES/CWE-120/UnboundedWrite.ql" \
    "$QUERIES/CWE-190/IntegerOverflowTainted.ql" \
    "$QUERIES/CWE-129/ImproperArrayIndexValidation.ql" \
    "$QUERIES/CWE-457/ConditionallyUninitializedVariable.ql" \
    "$QUERIES/CWE-468/SuspiciousAddWithSizeof.ql" \
    --format=sarif-latest \
    --output="$RES/codeql-cwe-1.0.30.sarif"

echo "== своё правило"
for version in 1.0.30 1.1.0; do
    "$CODEQL" database analyze "$ROOT/work/db-$version" \
        "$ROOT/rules/codeql/msadpcm-block-size.ql" \
        --format=sarif-latest \
        --output="$RES/codeql-custom-$version.sarif"
done
