#!/usr/bin/env python3
"""Разбор APK для лабораторной 5: манифест, native-методы, вызовы опасных API.

Native-метод считается sink: из Java/Kotlin управление уходит в неуправляемый код.
Скрипт не строит xref и не декомпилирует методы, только флаги доступа и байткод.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

from androguard.core.apk import APK
from androguard.core.axml import AXMLPrinter
from androguard.core.dex import DEX

NS = "{http://schemas.android.com/apk/res/android}"
ACC_NATIVE = 0x100
PRIM = {
    "V": "void",
    "Z": "boolean",
    "B": "byte",
    "S": "short",
    "C": "char",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
}

# Подстрока smali-вызова -> короткое имя для отчёта.
PATTERNS = [
    ("loadLibrary", "Ljava/lang/System;->loadLibrary"),
    ("systemLoad", "Ljava/lang/System;->load("),
    ("runtimeExec", "Ljava/lang/Runtime;->exec"),
    ("processBuilder", "Ljava/lang/ProcessBuilder;-><init>"),
    ("webviewLoadUrl", "Landroid/webkit/WebView;->loadUrl"),
    ("webviewLoadData", "Landroid/webkit/WebView;->loadData"),
    ("addJavascriptInterface", "addJavascriptInterface"),
    ("setJavaScriptEnabled", "setJavaScriptEnabled"),
    ("evaluateJavascript", "evaluateJavascript"),
    ("setAllowFileAccess", "setAllowFileAccess"),
    ("setAllowUniversalAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs"),
    ("shouldOverrideUrlLoading", "shouldOverrideUrlLoading"),
    ("cipherGetInstance", "Ljavax/crypto/Cipher;->getInstance"),
    ("messageDigest", "Ljava/security/MessageDigest;->getInstance"),
    ("secretKeySpec", "Ljavax/crypto/spec/SecretKeySpec;-><init>"),
    ("trustManagerCheck", "checkServerTrusted"),
    ("hostnameVerifier", "verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)"),
    ("sslContext", "Ljavax/net/ssl/SSLContext;->getInstance"),
    ("certificatePinner", "Lokhttp3/CertificatePinner;"),
    ("httpURLConnection", "Ljava/net/HttpURLConnection;->"),
    ("httpsURLConnection", "Ljavax/net/ssl/HttpsURLConnection;->"),
    ("okhttpNewCall", "Lokhttp3/OkHttpClient;->newCall"),
    ("okhttpUrl", "Lokhttp3/Request$Builder;->url"),
    ("openFileOutput", "->openFileOutput("),
    ("getSharedPreferences", "->getSharedPreferences("),
    ("rawQuery", "->rawQuery("),
    ("execSQL", "->execSQL("),
    ("contentQuery", "Landroid/content/ContentResolver;->query"),
    ("openInputStream", "->openInputStream("),
    ("intentGetData", "Landroid/content/Intent;->getData("),
    ("intentGetDataString", "Landroid/content/Intent;->getDataString("),
    ("intentGetStringExtra", "Landroid/content/Intent;->getStringExtra("),
    ("intentGetParcelableExtra", "Landroid/content/Intent;->getParcelableExtra("),
    ("intentGetClipData", "Landroid/content/Intent;->getClipData("),
    ("sendBroadcast", "->sendBroadcast("),
    ("startActivity", "->startActivity("),
    ("logd", "Landroid/util/Log;->d("),
    ("loge", "Landroid/util/Log;->e("),
    ("fileOutputStreamInit", "Ljava/io/FileOutputStream;-><init>"),
    ("fileInputStreamInit", "Ljava/io/FileInputStream;-><init>"),
    ("dexClassLoader", "Ldalvik/system/DexClassLoader;"),
    ("pathClassLoader", "Ldalvik/system/PathClassLoader;"),
    ("webviewSettings", "Landroid/webkit/WebSettings;->"),
]


def attr(el, name: str):
    if el is None:
        return None
    return el.get(NS + name)


def parse_type(desc: str, i: int) -> tuple[str, int]:
    c = desc[i]
    if c in PRIM:
        return PRIM[c], i + 1
    if c == "L":
        j = desc.index(";", i)
        return desc[i + 1 : j].replace("/", "."), j + 1
    if c == "[":
        inner, i2 = parse_type(desc, i + 1)
        return inner + "[]", i2
    raise ValueError(f"плохой дескриптор {desc!r} на {i}")


def flowdroid_sink(class_name: str, method: str, proto: str) -> str:
    cls = class_name[1:-1].replace("/", ".")
    if not proto.startswith("("):
        raise ValueError(proto)
    i = 1
    args = []
    while proto[i] != ")":
        typ, i = parse_type(proto, i)
        args.append(typ)
    ret, _ = parse_type(proto, i + 1)
    return f"<{cls}: {ret} {method}({','.join(args)})> -> _SINK_"


def intent_filters(el) -> list[dict]:
    found = []
    for filt in el.findall("intent-filter"):
        item = {
            "actions": [attr(a, "name") for a in filt.findall("action")],
            "categories": [attr(c, "name") for c in filt.findall("category")],
            "data": [],
        }
        for data in filt.findall("data"):
            spec = {}
            for key in (
                "scheme",
                "host",
                "port",
                "path",
                "pathPrefix",
                "pathPattern",
                "mimeType",
            ):
                value = attr(data, key)
                if value:
                    spec[key] = value
            if spec:
                item["data"].append(spec)
        found.append(item)
    return found


def component_record(el) -> dict:
    return {
        "name": attr(el, "name"),
        "exported": attr(el, "exported"),
        "permission": attr(el, "permission"),
        "authorities": attr(el, "authorities"),
        "grantUriPermissions": attr(el, "grantUriPermissions"),
        "process": attr(el, "process"),
        "intent_filters": intent_filters(el),
    }


def write_manifest(a: APK, out_dir: Path) -> dict:
    root = a.get_android_manifest_xml()
    app = root.find("application")
    info = {
        "package": a.get_package(),
        "version_name": a.get_androidversion_name(),
        "version_code": a.get_androidversion_code(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "max_sdk": a.get_max_sdk_version(),
        "permissions": sorted(set(a.get_permissions())),
        "declared_permissions": [],
        "application": {
            "debuggable": attr(app, "debuggable"),
            "allowBackup": attr(app, "allowBackup"),
            "usesCleartextTraffic": attr(app, "usesCleartextTraffic"),
            "networkSecurityConfig": attr(app, "networkSecurityConfig"),
            "extractNativeLibs": attr(app, "extractNativeLibs"),
            "name": attr(app, "name"),
            "testOnly": attr(app, "testOnly"),
        },
        "activities": [component_record(el) for el in root.findall(".//activity")],
        "activity_aliases": [component_record(el) for el in root.findall(".//activity-alias")],
        "services": [component_record(el) for el in root.findall(".//service")],
        "receivers": [component_record(el) for el in root.findall(".//receiver")],
        "providers": [component_record(el) for el in root.findall(".//provider")],
    }
    for perm in root.findall("permission"):
        info["declared_permissions"].append(
            {
                "name": attr(perm, "name"),
                "protectionLevel": attr(perm, "protectionLevel"),
            }
        )
    nsc = a.get_file("res/xml/network_security_config.xml")
    if nsc:
        try:
            printed = AXMLPrinter(nsc).get_xml()
            if isinstance(printed, bytes):
                info["network_security_config_xml"] = printed.decode("utf-8", "replace")
            else:
                info["network_security_config_xml"] = str(printed)
        except Exception as exc:  # битый XML не должен ронять весь разбор
            info["network_security_config_xml"] = f"ошибка разбора: {exc}"
    (out_dir / "manifest.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return info


def manifest_text(info: dict) -> str:
    lines = [
        f"package {info['package']}",
        f"versionName {info['version_name']} versionCode {info['version_code']}",
        f"minSdk {info['min_sdk']} targetSdk {info['target_sdk']}",
        f"application {json.dumps(info['application'], ensure_ascii=False)}",
        f"uses-permission {len(info['permissions'])}",
    ]
    lines.extend(f"  {p}" for p in info["permissions"])
    lines.append(f"declared permission {len(info['declared_permissions'])}")
    for perm in info["declared_permissions"]:
        lines.append(f"  {perm['name']} protectionLevel={perm['protectionLevel']}")

    def dump(kind: str, items: list[dict]) -> None:
        opened = []
        for item in items:
            exported = item["exported"]
            filters = item["intent_filters"]
            # На targetSdk 31+ компонент с intent-filter без exported не ставится.
            # Считаем входной точкой явный exported=true и любой intent-filter.
            if exported == "true" or filters:
                opened.append(item)
        lines.append(f"{kind}: всего {len(items)}, с exported=true или intent-filter {len(opened)}")
        for item in opened:
            lines.append(
                f"  {item['name']} exported={item['exported']} permission={item['permission']}"
            )
            if item.get("authorities"):
                lines.append(f"    authorities {item['authorities']}")
            for filt in item["intent_filters"]:
                lines.append(
                    "    filter actions="
                    + ",".join(x or "" for x in filt["actions"])
                    + " categories="
                    + ",".join(x or "" for x in filt["categories"])
                    + " data="
                    + json.dumps(filt["data"], ensure_ascii=False)
                )

    dump("activity", info["activities"])
    dump("activity-alias", info["activity_aliases"])
    dump("service", info["services"])
    dump("receiver", info["receivers"])
    dump("provider", info["providers"])
    if info.get("network_security_config_xml"):
        lines.append("network_security_config:")
        lines.append(info["network_security_config_xml"])
    return "\n".join(lines) + "\n"


def scan_dex(a: APK, out_dir: Path) -> None:
    natives = []
    load_sites = []
    hits = defaultdict(lambda: {"count": 0, "examples": []})
    method_count = 0
    class_count = 0
    dex_files = list(a.get_all_dex())
    print(f"dex files: {len(dex_files)}", flush=True)
    for index, dex_bytes in enumerate(dex_files, start=1):
        print(f"parse dex {index}/{len(dex_files)} bytes {len(dex_bytes)}", flush=True)
        dex = DEX(dex_bytes)
        for cls in dex.get_classes():
            class_count += 1
            for method in cls.get_methods():
                method_count += 1
                if method.get_access_flags() & ACC_NATIVE:
                    natives.append(
                        {
                            "class": method.get_class_name(),
                            "name": method.get_name(),
                            "descriptor": method.get_descriptor(),
                            "access": method.get_access_flags_string(),
                        }
                    )
                    continue
                code = method.get_code()
                if code is None:
                    continue
                strings = []
                invokes = []
                for ins in method.get_instructions():
                    op = ins.get_name()
                    if op in ("const-string", "const-string/jumbo"):
                        output = ins.get_output()
                        # формат: v0, "text"
                        quote = output.find('"')
                        if quote != -1:
                            strings.append(output[quote + 1 :].rstrip('"'))
                    elif op.startswith("invoke"):
                        invokes.append(ins.get_output())
                if not invokes:
                    continue
                joined_libs = any("loadLibrary" in item or "->load(" in item for item in invokes)
                if joined_libs:
                    load_sites.append(
                        {
                            "class": method.get_class_name(),
                            "method": method.get_name(),
                            "descriptor": method.get_descriptor(),
                            "strings": strings[:20],
                            "invokes": [item for item in invokes if "load" in item][:8],
                        }
                    )
                where = f"{method.get_class_name()} {method.get_name()}{method.get_descriptor()}"
                for name, needle in PATTERNS:
                    matched = [item for item in invokes if needle in item]
                    if not matched:
                        continue
                    bucket = hits[name]
                    bucket["count"] += len(matched)
                    if len(bucket["examples"]) < 8:
                        bucket["examples"].append(
                            {"where": where, "invoke": matched[0][:300]}
                        )
        print(
            f"dex {index} done classes {class_count} methods {method_count} natives {len(natives)}",
            flush=True,
        )

    native_path = out_dir / "natives.json"
    native_path.write_text(json.dumps(natives, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = [f"native methods: {len(natives)}", f"classes: {class_count}", f"methods: {method_count}", ""]
    for item in natives:
        lines.append(f"{item['access']} {item['class']}->{item['name']}{item['descriptor']}")
    (out_dir / "natives.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    sinks = []
    for item in natives:
        try:
            sinks.append(flowdroid_sink(item["class"], item["name"], item["descriptor"]))
        except ValueError as exc:
            sinks.append(f"# пропущен {item['class']}->{item['name']}: {exc}")
    (out_dir / "native-sinks.txt").write_text("\n".join(sinks) + "\n", encoding="utf-8")

    (out_dir / "load-libraries.json").write_text(
        json.dumps(load_sites, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out_dir / "api-hits.json").write_text(
        json.dumps(hits, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    summary = [f"classes {class_count}", f"methods {method_count}", f"natives {len(natives)}", f"load sites {len(load_sites)}", ""]
    for name, _needle in PATTERNS:
        summary.append(f"{name}\t{hits[name]['count']}")
    (out_dir / "api-hits.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary), flush=True)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: audit_apk.py APK OUT_DIR", file=sys.stderr)
        return 2
    apk_path, out_dir = sys.argv[1], Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"open {apk_path}", flush=True)
    apk = APK(apk_path)
    info = write_manifest(apk, out_dir)
    text = manifest_text(info)
    (out_dir / "manifest.txt").write_text(text, encoding="utf-8")
    print(text, flush=True)
    scan_dex(apk, out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
