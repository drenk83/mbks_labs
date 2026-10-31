#!/usr/bin/env python3
"""Собирает короткие сводки по результатам прогонов для отчёта."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"


def sarif_counts(path: Path) -> Counter[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    counts: Counter[str] = Counter()
    for run in data.get("runs", []):
        for result in run.get("results", []):
            counts[result.get("ruleId", "?")] += 1
    return counts


def write_codeql_summary() -> None:
    cwe = sarif_counts(RESULTS / "codeql-cwe-1.0.30.sarif")
    # CWE-120 не дал срабатываний, но в сводке он должен быть.
    cwe["cpp/unbounded-write"] += 0
    custom_vuln = sarif_counts(RESULTS / "codeql-custom-1.0.30.sarif")
    custom_fixed = sarif_counts(RESULTS / "codeql-custom-1.1.0.sarif")

    lines = ["CodeQL, libsndfile 1.0.30: пять штатных запросов", ""]
    lines.append(f"{'запрос':48s} {'находок':>8s}")
    for rule, count in cwe.most_common():
        lines.append(f"{rule:48s} {count:8d}")
    lines.append(f"{'ИТОГО':48s} {sum(cwe.values()):8d}")
    lines += [
        "",
        "Своё правило cpp/lab4-msadpcm-block-size:",
        f"  libsndfile 1.0.30: {sum(custom_vuln.values())} находка",
        f"  libsndfile 1.1.0: {sum(custom_fixed.values())} находок",
    ]
    (RESULTS / "codeql-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_semgrep_summary() -> None:
    lines = ["semgrep, libsndfile 1.0.30", ""]

    for title, path in [
        ("p/c (штатный C-набор)", RESULTS / "semgrep-builtin-1.0.30.txt"),
        ("p/default", RESULTS / "semgrep-default-1.0.30.txt"),
        ("p/security-audit", RESULTS / "semgrep-security-audit-1.0.30.txt"),
    ]:
        text = path.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"Ran (\d+) rules? on (\d+) files?: (\d+) findings?", text)
        lines.append(f"{title}: {m.group(3)} находок ({m.group(1)} правил, {m.group(2)} файлов)" if m else f"{title}: см. {path.name}")

    audit = json.loads((RESULTS / "semgrep-security-audit-1.0.30.json").read_text(encoding="utf-8"))
    counts: Counter[str] = Counter(r["check_id"] for r in audit.get("results", []))
    lines += ["", "p/security-audit по правилам:"]
    for rule, count in counts.most_common():
        lines.append(f"  {count:2d}  {rule}")

    lines += ["", "Своё правило lab4-msadpcm-block-size:"]
    for version in ("1.0.30", "1.1.0"):
        text = (RESULTS / f"semgrep-custom-{version}.txt").read_text(encoding="utf-8", errors="replace")
        m = re.search(r"Ran 1 rule on \d+ files?: (\d+) findings?", text)
        lines.append(f"  libsndfile {version}: {m.group(1) if m else '?'} находок")

    (RESULTS / "semgrep-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_poc_summary() -> None:
    vuln = (RESULTS / "poc-1.0.30-asan.log").read_text(encoding="utf-8", errors="replace")
    fixed = (RESULTS / "poc-1.1.0-asan.log").read_text(encoding="utf-8", errors="replace")
    keep = [
        line
        for line in vuln.splitlines()
        if "ERROR: AddressSanitizer" in line
        or "WRITE of size" in line
        or "msadpcm_decode_block" in line
        or "SUMMARY: AddressSanitizer" in line
        or "allocated by thread" in line
    ][:6]
    fixed_lines = [line for line in fixed.splitlines() if "samplesperblock" in line or "Error" in line][:3]
    lines = [
        "libsndfile 1.0.30 + ASan (PoC 2660 байт):",
        *keep,
        "",
        "libsndfile 1.1.0 + ASan (тот же файл):",
        *fixed_lines,
    ]
    (RESULTS / "poc-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_joern_summary() -> None:
    text = (RESULTS / "joern-builtin-1.0.30.txt").read_text(encoding="utf-8", errors="replace")
    counts: Counter[tuple[str, str]] = Counter()
    for line in text.splitlines():
        if not line.startswith("Result: "):
            continue
        rest = line[len("Result: ") :]
        score, _, tail = rest.partition(" : ")
        title_file, _, _ = tail.rpartition(":")
        title_file, _, _ = title_file.rpartition(":")
        title, _, _ = title_file.rpartition(": ")
        if title:
            counts[(score, title)] += 1

    lines = [
        "joern-scan --language c, libsndfile 1.0.30, каталог src/",
        f"строк Result: {sum(counts.values())}",
        "",
        f"{'находок':>7}  {'балл':4}  запрос",
    ]
    for (score, title), count in counts.most_common():
        lines.append(f"{count:7d}  {score:4}  {title}")
    lines += [
        "",
        "CVE-2021-3246 в штатном наборе нет.",
        "Своё правило, 1.0.30:",
        (RESULTS / "joern-custom-1.0.30.txt").read_text(encoding="utf-8").rstrip(),
        "Своё правило, 1.1.0:",
        (RESULTS / "joern-custom-1.1.0.txt").read_text(encoding="utf-8").rstrip(),
    ]
    (RESULTS / "joern-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    custom = [
        "libsndfile 1.0.30",
        (RESULTS / "joern-custom-1.0.30.txt").read_text(encoding="utf-8").rstrip(),
        "",
        "libsndfile 1.1.0",
        (RESULTS / "joern-custom-1.1.0.txt").read_text(encoding="utf-8").rstrip(),
    ]
    (RESULTS / "joern-custom-summary.txt").write_text("\n".join(custom) + "\n", encoding="utf-8")


def main() -> None:
    write_codeql_summary()
    write_semgrep_summary()
    write_poc_summary()
    write_joern_summary()
    print("сводки записаны в", RESULTS)


if __name__ == "__main__":
    main()
