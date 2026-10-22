#!/usr/bin/env python3
"""secops.py - zero-dependency helpers for authorized security work.

Subcommands:
  ioc      Extract and defang indicators from text files/directories/stdin.
  hash     Hash files, estimate entropy, and identify common file types.
  triage   Normalize/dedupe/prioritize findings from CSV or JSON.
  http     Single-request HTTP hardening check, gated by authorization+scope.
  redact   Redact secrets/PII from reports before sharing.

Only the `http` subcommand makes network requests. It requires both
--i-have-authorization and at least one --scope-file. It performs GET/HEAD
requests with limited redirects; it does not crawl, fuzz, or exploit.

Python 3.10+; standard library only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import http.client
import io
import ipaddress
import json
import math
import re
import socket
import ssl
import sys
import time
import urllib.parse
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

VERSION = "1.1.0"
DEFAULT_UA = "cybersecurity-ops-secops/1.1 (authorized security review)"
MAX_TEXT_BYTES = 10 * 1024 * 1024
MAX_HTTP_BYTES = 256 * 1024

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

URL_RE = re.compile(r"\bhttps?://[^\s<>'\"`]+", re.IGNORECASE)
EMAIL_RE = re.compile(
    r"(?<![\w.+-])[\w.+-]{1,64}@(?:[\w-]+\.)+[A-Za-z]{2,24}(?![\w-])"
)
HASH_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(
    r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])"
)
DOMAIN_RE = re.compile(
    r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,24})(?![\w-])"
)

# Common gTLDs plus ccTLDs (any two-letter TLD is accepted, except file
# extensions below). This is a heuristic, not a public suffix list.
COMMON_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
    "pro", "museum", "coop", "aero", "jobs", "mobi", "travel", "tel", "asia",
    "cat", "xxx", "io", "ai", "app", "dev", "cloud", "tech", "online", "site",
    "store", "shop", "blog", "xyz", "top", "club", "live", "news", "media",
    "agency", "solutions", "services", "systems", "network", "security",
    "software", "digital", "global", "group", "world", "today", "space",
    "website", "host", "page", "link", "click", "download", "stream", "video",
    "music", "photo", "email", "social", "community", "academy", "school",
    "university", "institute", "foundation", "consulting", "finance",
    "financial", "bank", "insurance", "capital", "investments", "ventures",
    "partners", "legal", "law", "health", "care", "clinic", "hospital",
    "pharmacy", "fitness", "coffee", "food", "restaurant", "hotel", "tours",
    "flights", "cargo", "logistics", "transport", "energy", "solar", "green",
    "earth", "eco", "farm", "garden", "home", "house", "properties",
    "realestate", "construction", "build", "tools", "equipment", "supply",
    "industries", "engineering", "technology", "computer", "electronics",
    "auto", "cars", "bike", "boats", "yachts", "sale", "deals", "discount",
    "coupons", "free", "win", "bid", "loan", "credit", "card", "money",
    "cash", "exchange", "market", "trading", "stocks", "fund", "tax",
    "attorney", "doctor", "dentist", "lawyer", "realtor", "photography",
    "graphics", "design", "studio", "productions", "events", "wedding",
    "gifts", "flowers", "toys", "games", "gaming", "esports", "bet", "poker",
    "casino", "vegas", "adult", "dating", "porn", "vip", "luxury", "style",
    "fashion", "shoes", "jewelry", "watches", "beauty", "spa", "yoga", "run",
    "golf", "tennis", "soccer", "football", "basketball", "hockey",
    "baseball", "cricket", "rugby", "racing", "motors", "trucks", "taxi",
    "limo", "airline", "airport", "cruises", "vacations", "holiday", "hotels",
    "cafe", "bar", "pub", "beer", "wine", "recipes", "cooking", "kitchen",
    "menu", "pizza", "tea", "organic", "wind", "water", "recycle", "charity",
    "ngo", "church", "faith", "love", "life", "vlog", "tube", "radio", "tv",
    "movie", "film", "cinema", "theater", "band", "jazz", "dance", "art",
    "gallery", "pics", "images", "onion",
}

# File extensions that commonly appear as domains in text but are not.
FILE_EXTENSIONS = {
    "py", "pyc", "pyo", "js", "mjs", "cjs", "ts", "tsx", "jsx", "vue", "svelte",
    "md", "mdx", "txt", "rst", "log", "csv", "tsv", "json", "jsonl", "yaml",
    "yml", "toml", "ini", "cfg", "conf", "xml", "html", "htm", "xhtml", "css",
    "scss", "less", "svg", "ico", "woff", "woff2", "ttf", "eot", "otf",
    "php", "phtml", "asp", "aspx", "jsp", "jspx", "cgi", "pl", "rb", "go",
    "rs", "java", "kt", "kts", "scala", "cs", "fs", "vb", "c", "h", "cc",
    "cpp", "cxx", "hpp", "m", "mm", "swift", "sh", "bash", "zsh", "fish",
    "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "wsf", "hta",
    "exe", "dll", "sys", "drv", "so", "dylib", "bin", "dat", "db", "sqlite",
    "sqlite3", "mdb", "accdb", "zip", "gz", "tgz", "bz2", "xz", "7z", "rar",
    "tar", "iso", "img", "vhd", "vhdx", "vmdk", "qcow2", "ova", "ovf",
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "psd", "ai",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp",
    "rtf", "epub", "mobi", "azw", "azw3", "mp3", "wav", "flac", "ogg", "m4a",
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "apk", "ipa",
    "jar", "war", "ear", "class", "dex", "elf", "pcap", "pcapng", "cap",
    "lock", "map", "min", "local", "internal", "localhost", "test", "example",
    "invalid", "arpa",
}

TYPE_ORDER = [
    "url", "domain", "ipv4", "ipv6", "md5", "sha1", "sha256", "cve", "email",
]


class UserError(Exception):
    """Expected user-facing error."""


def eprint(*args: Any, **kwargs: Any) -> None:
    print(*args, file=sys.stderr, **kwargs)


def emit(text: str, output: Optional[str]) -> None:
    if output:
        path = Path(output)
        if path.parent and str(path.parent) not in ("", "."):
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        eprint(f"wrote {path}")
        return
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")


def md(value: Any) -> str:
    text = html.escape(str(value), quote=False)
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", text)
    return re.sub(r"([\\`*_{\[\]()#!|>~}])", r"\\\1", text)


def csv_safe(row: Dict[str, Any]) -> Dict[str, Any]:
    """Keep spreadsheet applications from evaluating untrusted text cells."""
    return {
        key: "'" + value if isinstance(value, str) and (
            value.lstrip().startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠"))
            or value.startswith(("\t", "\r", "\n"))
        ) else value
        for key, value in row.items()
    }


def read_text_bounded(path: Optional[Path] = None, encoding: str = "utf-8") -> str:
    if path is None:
        text = sys.stdin.read(MAX_TEXT_BYTES + 1)
        if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            raise UserError(f"input exceeds {MAX_TEXT_BYTES} bytes")
        return text
    with path.open("rb") as handle:
        data = handle.read(MAX_TEXT_BYTES + 1)
    if len(data) > MAX_TEXT_BYTES:
        raise UserError(f"input exceeds {MAX_TEXT_BYTES} bytes: {path}")
    return data.decode(encoding, errors="replace")


def defang(value: str, kind: str) -> str:
    if kind in ("url", "domain", "ipv4", "email"):
        out = re.sub(r"(?i)^https://", "hxxps://", value)
        out = re.sub(r"(?i)^http://", "hxxp://", out)
        out = out.replace(".", "[.]")
        if kind == "email":
            out = out.replace("@", "[@]")
        return out
    if kind == "ipv6":
        return value.replace(":", "[:]")
    return value


def refang(text: str) -> str:
    text = re.sub(r"(?i)hxxps://", "https://", text)
    text = re.sub(r"(?i)hxxp://", "http://", text)
    text = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", text)
    text = text.replace("[dot]", ".").replace("(dot)", ".")
    text = text.replace("[:]", ":").replace("[@]", "@")
    return text


def is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def is_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    value = value.strip().strip(".").lower()
    if len(value) < 4 or len(value) > 253 or ".." in value:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if not tld.isalpha() or tld in FILE_EXTENSIONS:
        return False
    if tld not in COMMON_TLDS and len(tld) != 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False
    return True


def is_url(value: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return False
    host = parts.hostname
    return is_ipv4(host) or is_ipv6(host) or is_domain(host)


def clean_url(value: str) -> str:
    return value.rstrip(".,;:!?)]}>'\"`")


def extract_iocs(text: str, include_emails: bool = False) -> List[Tuple[str, str]]:
    """Extract indicators from a single line (or short text).

    Returns (type, value) tuples. Values are refanged/canonicalized where
    appropriate; display defanging is a separate step.
    """
    text = refang(text)
    found: List[Tuple[str, str]] = []

    for match in URL_RE.finditer(text):
        value = clean_url(match.group(0))
        if is_url(value):
            found.append(("url", value))

    for match in HASH_RE.finditer(text):
        value = match.group(0).lower()
        kind = {64: "sha256", 40: "sha1", 32: "md5"}[len(value)]
        found.append((kind, value))

    for match in CVE_RE.finditer(text):
        found.append(("cve", match.group(0).upper()))

    for match in IPV4_RE.finditer(text):
        value = match.group(0)
        if is_ipv4(value):
            found.append(("ipv4", value))

    for match in IPV6_RE.finditer(text):
        value = match.group(0)
        if is_ipv6(value):
            found.append(("ipv6", value.lower()))

    for match in DOMAIN_RE.finditer(text):
        value = match.group(0).lower().rstrip(".")
        if is_domain(value):
            found.append(("domain", value))

    if include_emails:
        for match in EMAIL_RE.finditer(text):
            value = match.group(0).lower().rstrip(".")
            domain = value.rsplit("@", 1)[-1]
            if is_domain(domain):
                found.append(("email", value))

    return found


# ---------------------------------------------------------------------------
# IOC command
# ---------------------------------------------------------------------------

IOC_FIELDS = ["type", "value", "defanged", "occurrences", "sources", "context"]


def _iter_input_files(paths: Sequence[str]) -> Iterable[Tuple[str, str]]:
    if not paths:
        yield "<stdin>", read_text_bounded()
        return
    for raw in paths:
        if raw == "-":
            yield "<stdin>", read_text_bounded()
            continue
        path = Path(raw)
        if not path.exists():
            raise UserError(f"input not found: {path}")
        if path.is_file():
            files = [path]
        else:
            files = sorted(p for p in path.rglob("*") if p.is_file() and not p.is_symlink()
                           and not getattr(p, "is_junction", lambda: False)())
        for item in files:
            try:
                if item.stat().st_size > MAX_TEXT_BYTES:
                    eprint(f"skip large file: {item}")
                    continue
                with item.open("rb") as handle:
                    data = handle.read(MAX_TEXT_BYTES + 1)
                if len(data) > MAX_TEXT_BYTES:
                    raise UserError(f"input grew beyond size limit: {item}")
            except OSError as exc:
                eprint(f"skip {item}: {exc}")
                continue
            if b"\x00" in data[:4096]:
                eprint(f"skip binary file: {item}")
                continue
            yield str(item), data.decode("utf-8", errors="replace")


def collect_iocs(
    paths: Sequence[str], include_emails: bool, redact_context: bool = True
) -> List[Dict[str, Any]]:
    records: "OrderedDict[Tuple[str, str], Dict[str, Any]]" = OrderedDict()
    for source, text in _iter_input_files(paths):
        # Redact before splitting/truncating: PEM keys may span many lines,
        # and a secret that looks like a hash must not become an indicator.
        safe_lines = redact_text(text).splitlines()
        raw_lines = text.splitlines() if not redact_context else safe_lines
        for lineno, safe_line in enumerate(safe_lines):
            raw_line = raw_lines[lineno] if lineno < len(raw_lines) else safe_line
            line = refang(safe_line)
            context = raw_line.strip()[:200]
            for kind, value in extract_iocs(line, include_emails=include_emails):
                key_value = value if kind == "url" else value.lower()
                key = (kind, key_value)
                rec = records.get(key)
                if rec is None:
                    rec = {
                        "type": kind,
                        "value": value,
                        "defanged": defang(value, kind),
                        "occurrences": 0,
                        "sources": [],
                        "context": context,
                    }
                    records[key] = rec
                rec["occurrences"] += 1
                if source not in rec["sources"] and len(rec["sources"]) < 10:
                    rec["sources"].append(source)
    result = list(records.values())
    result.sort(key=lambda r: (TYPE_ORDER.index(r["type"]), r["value"]))
    return result


def render_iocs(items: List[Dict[str, Any]], fmt: str) -> str:
    if fmt == "json":
        counts = Counter(item["type"] for item in items)
        payload = {
            "tool": f"secops.py {VERSION}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(items),
            "by_type": dict(sorted(counts.items())),
            "indicators": items,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=IOC_FIELDS, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        for item in items:
            row = dict(item)
            row["sources"] = "; ".join(item["sources"])
            writer.writerow(csv_safe(row))
        return buf.getvalue()
    lines = [
        "# Indicator extract",
        "",
        f"Total: **{len(items)}** unique indicator(s).  Values below are defanged.",
        "",
        "| Type | Value (defanged) | Count | Sources | Context |",
        "|---|---|---:|---|---|",
    ]
    for item in items:
        lines.append(
            "| {type} | `{value}` | {count} | {sources} | {context} |".format(
                type=md(item["type"]),
                value=md(item["defanged"]),
                count=item["occurrences"],
                sources=md(", ".join(item["sources"])),
                context=md(item["context"]),
            )
        )
    lines.append("")
    return "\n".join(lines)


def cmd_ioc(args: argparse.Namespace) -> int:
    items = collect_iocs(
        args.paths,
        include_emails=args.include_emails,
        redact_context=args.redact_context,
    )
    if args.types:
        allowed = {t.lower() for t in args.types}
        unknown = allowed - set(TYPE_ORDER)
        if unknown:
            raise UserError(f"unknown --types: {', '.join(sorted(unknown))}")
        items = [item for item in items if item["type"] in allowed]
    emit(render_iocs(items, args.format), args.output)
    return 0


# ---------------------------------------------------------------------------
# Hash command
# ---------------------------------------------------------------------------

def detect_magic(head: bytes) -> str:
    if head.startswith(b"MZ"):
        return "PE/Windows executable"
    if head.startswith(b"\x7fELF"):
        return "ELF executable"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O executable"
    if head.startswith(b"%PDF"):
        return "PDF document"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP/Office/APK archive"
    if head.startswith(b"\x1f\x8b"):
        return "gzip stream"
    if head.startswith(b"BZh"):
        return "bzip2 stream"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz stream"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z archive"
    if head.startswith(b"Rar!\x1a\x07"):
        return "RAR archive"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE/legacy Office document"
    if head.startswith(b"{\\rtf"):
        return "RTF document"
    if head.startswith(b"#!"):
        return "script with shebang"
    if head.startswith(b"SQLite format 3\x00"):
        return "SQLite database"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return "GIF image"
    if not head:
        return "empty"
    printable = sum(1 for b in head if b in b"\t\r\n" or 32 <= b < 127)
    if printable / len(head) > 0.9:
        return "text/data (printable)"
    return "unknown binary"


def entropy_from_counts(counts: Sequence[int], total: int) -> float:
    if total <= 0:
        return 0.0
    result = 0.0
    for count in counts:
        if count:
            p = count / total
            result -= p * math.log2(p)
    return result


def describe_file(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise UserError(f"not a file: {path}")
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    counts = [0] * 256
    total = 0
    head = b""
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            if len(head) < 64:
                head += chunk[: 64 - len(head)]
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            total += len(chunk)
            for byte, count in Counter(chunk).items():
                counts[byte] += count
    return {
        "path": str(path),
        "size": total,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "entropy": round(entropy_from_counts(counts, total), 4),
        "magic": detect_magic(head),
    }


def render_hashes(items: List[Dict[str, Any]], fmt: str) -> str:
    if fmt == "json":
        payload = {
            "tool": f"secops.py {VERSION}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "files": items,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if fmt == "csv":
        fields = ["path", "size", "magic", "entropy", "md5", "sha1", "sha256"]
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(csv_safe(item) for item in items)
        return buf.getvalue()
    lines = [
        "# File hashes",
        "",
        "| File | Size | Magic | Entropy | SHA-256 |",
        "|---|---:|---|---:|---|",
    ]
    for item in items:
        lines.append(
            "| `{path}` | {size} | {magic} | {entropy} | `{sha}` |".format(
                path=md(item["path"]),
                size=item["size"],
                magic=md(item["magic"]),
                entropy=item["entropy"],
                sha=item["sha256"],
            )
        )
    lines.append("")
    return "\n".join(lines)


def cmd_hash(args: argparse.Namespace) -> int:
    items = [describe_file(Path(p)) for p in args.paths]
    if args.sha256:
        expected = args.sha256.lower().strip()
        if len(items) != 1:
            raise UserError("--sha256 expects exactly one input file")
        actual = items[0]["sha256"]
        status = "MATCH" if actual == expected else "MISMATCH"
        eprint(f"{status}: {actual}")
        emit(render_hashes(items, args.format), args.output)
        return 0 if status == "MATCH" else 1
    emit(render_hashes(items, args.format), args.output)
    return 0


# ---------------------------------------------------------------------------
# Triage command
# ---------------------------------------------------------------------------

FIELD_ALIASES: Dict[str, Tuple[str, ...]] = {
    "id": ("id", "finding_id", "ref", "reference"),
    "title": ("title", "name", "finding", "vulnerability", "issue", "summary"),
    "asset": ("asset", "host", "target", "url", "endpoint", "resource", "ip"),
    "severity": ("severity", "risk", "scanner_severity", "criticality"),
    "cvss": ("cvss", "cvss_score", "cvss_base", "cvss_v3", "cvss_v4", "score"),
    "cve": ("cve", "cve_id", "cves", "vulnerability_id"),
    "epss": ("epss", "epss_score", "epss_probability"),
    "kev": ("kev", "cisa_kev", "known_exploited", "in_the_wild"),
    "exposed": ("exposed", "internet_exposed", "internet_facing", "public", "external"),
    "sensitive": ("sensitive", "data_sensitive", "pii", "regulated", "confidential"),
    "confidence": ("confidence", "confidence_score", "certainty"),
    "source": ("source", "scanner", "tool", "feed"),
    "evidence": ("evidence", "description", "details", "proof", "notes"),
    "status": ("status", "state"),
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": -1}
PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
SLA_DAYS = {"P0": 1, "P1": 7, "P2": 30, "P3": 90}
SEVERITY_IMPACT = {"critical": 0.95, "high": 0.80, "medium": 0.55, "low": 0.25, "info": 0.0}
ALLOWED_STATUS = {
    "observed", "suspected", "confirmed", "exploited",
    "fixed", "false_positive", "accepted", "unknown",
}


def norm_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def normalize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {norm_key(k): v for k, v in row.items() if k is not None}


def pick(row: Dict[str, Any], field_name: str) -> Any:
    for alias in FIELD_ALIASES[field_name]:
        if alias in row:
            value = row[alias]
            if value is None:
                continue
            if isinstance(value, str) and not value.strip():
                continue
            return value
    return None


def to_float(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            score = float(value)
        except OverflowError:
            return None
        return score if math.isfinite(score) else None
    text = str(value).strip()
    match = re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", text)
    if not match:
        return None
    try:
        score = float(match.group(0))
        return score if math.isfinite(score) else None
    except ValueError:
        return None


def to_bool(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return math.isfinite(value) and value != 0
    text = str(value).strip().lower()
    return text in {
        "1", "true", "yes", "y", "kev", "known", "confirmed",
        "in the wild", "in_the_wild", "public", "external",
        "internet", "internet-facing", "confidential", "pii",
    }


def to_kev(value: Any) -> bool:
    """KEV columns often contain a date (e.g. 2024-01-01), not a boolean.

    Only explicit positive values/ISO dates count. Unknown/N/A must not
    silently become KEV=yes and inflate the priority score.
    """
    if value is None:
        return False
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {
            "true", "yes", "y", "1", "kev", "known", "confirmed",
            "in the wild", "in_the_wild", "listed",
        }:
            return True
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            try:
                date.fromisoformat(text)
                return True
            except ValueError:
                return False
        return False
    return to_bool(value)


def norm_severity(value: Any, cvss: Optional[float]) -> str:
    if cvss is not None:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        if cvss > 0:
            return "low"
        return "info"
    text = str(value or "").strip().lower()
    mapping = {
        "critical": "critical", "crit": "critical", "severe": "critical",
        "high": "high", "important": "high",
        "medium": "medium", "moderate": "medium",
        "low": "low", "minor": "low",
        "info": "info", "informational": "info", "none": "info",
    }
    return mapping.get(text, "unknown")


def normalize_cvss(value: Any) -> Optional[float]:
    if isinstance(value, str) and "CVSS:" in value.upper():
        # A vector like CVSS:3.1/AV:N/... does not contain the base score.
        # Only accept an explicit trailing score, e.g. "... (9.8)".
        match = re.search(r"\((\d+(?:\.\d+)?)\)\s*$", value)
        if not match:
            return None
        score = float(match.group(1))
    else:
        score = to_float(value)
    if score is None:
        return None
    if 0.0 <= score <= 10.0:
        return score
    return None


def normalize_epss(value: Any) -> Optional[float]:
    percent = isinstance(value, str) and value.strip().endswith("%")
    score = to_float(value.strip()[:-1] if percent else value)
    if score is None:
        return None
    if percent or score > 1.0:
        score = score / 100.0
    if 0.0 <= score <= 1.0:
        return score
    return None


def normalize_confidence(value: Any) -> float:
    if isinstance(value, str):
        text = value.strip().lower()
        mapping = {
            "certain": 1.0, "high": 0.9, "medium": 0.7,
            "moderate": 0.7, "low": 0.4, "very low": 0.2,
        }
        if text in mapping:
            return mapping[text]
    percent = isinstance(value, str) and value.strip().endswith("%")
    score = to_float(value.strip()[:-1] if percent else value)
    if score is None:
        return 0.8
    if percent or score > 1.0:
        score = score / 100.0
    return max(0.0, min(1.0, score))


def normalize_status(value: Any) -> str:
    text = re.sub(r"[\s-]+", "_", str(value or "").strip().lower())
    aliases = {
        "falsepositive": "false_positive",
        "risk_accepted": "accepted",
        "accepted_risk": "accepted",
    }
    text = aliases.get(text, text)
    return text if text in ALLOWED_STATUS else "unknown"


def asset_key(asset: str) -> str:
    # URL paths and cloud resource IDs can be case-sensitive. Only a bare
    # DNS name (or the authority of a URL) is safe to case-fold.
    if "://" in asset:
        try:
            parts = urllib.parse.urlsplit(asset)
            return urllib.parse.urlunsplit((parts.scheme.lower(), parts.netloc.lower(),
                                            parts.path, parts.query, parts.fragment))
        except ValueError:
            return asset
    if re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]+)?", asset):
        return asset.lower()
    return asset


def context_known(value: Any, kind: str) -> bool:
    if kind == "kev" and to_kev(value):
        return True
    if kind == "confidence":
        if isinstance(value, str) and value.strip().lower() in (
            "certain", "high", "medium", "moderate", "low", "very low"
        ):
            return True
        text = value.strip().rstrip("%") if isinstance(value, str) else value
        number = to_float(text)
        return number is not None and 0 <= number <= 100
    return to_bool(value) or str(value).strip().lower() in ("0", "false", "no", "n")


def compute_priority(
    score: float,
    cvss: Optional[float],
    severity: str,
    kev: bool,
    exposed: bool,
    confidence: float,
) -> str:
    priority = "P3"
    if score >= 85.0:
        priority = "P0"
    elif score >= 70.0:
        priority = "P1"
    elif score >= 40.0:
        priority = "P2"

    critical = severity == "critical" or (cvss is not None and cvss >= 9.0)
    if confidence >= 0.8 and kev and exposed and critical:
        priority = "P0"
    elif confidence >= 0.7 and (kev or critical):
        if PRIORITY_RANK[priority] > PRIORITY_RANK["P1"]:
            priority = "P1"
    elif severity == "high" or (cvss is not None and cvss >= 7.0):
        if PRIORITY_RANK[priority] > PRIORITY_RANK["P2"]:
            priority = "P2"
    return priority


def normalize_finding(row: Dict[str, Any], index: int, source_name: str) -> Dict[str, Any]:
    row = normalize_row(row)
    cvss = normalize_cvss(pick(row, "cvss"))
    severity = norm_severity(pick(row, "severity"), cvss)
    epss = normalize_epss(pick(row, "epss"))
    kev = to_kev(pick(row, "kev"))
    exposed = to_bool(pick(row, "exposed"))
    sensitive = to_bool(pick(row, "sensitive"))
    confidence = normalize_confidence(pick(row, "confidence"))
    impact = (cvss / 10.0) if cvss is not None else SEVERITY_IMPACT.get(severity, 0.0)
    score = 100.0 * (
        0.50 * impact
        + 0.20 * (epss or 0.0)
        + 0.15 * (1.0 if kev else 0.0)
        + 0.10 * (1.0 if exposed else 0.0)
        + 0.05 * (1.0 if sensitive else 0.0)
    ) * confidence
    score = round(max(0.0, min(100.0, score)), 1)
    priority = compute_priority(score, cvss, severity, kev, exposed, confidence)

    title = str(pick(row, "title") or "Untitled finding").strip()
    asset = str(pick(row, "asset") or "unknown").strip()
    cve = str(pick(row, "cve") or "").strip().upper()
    finding_id = str(pick(row, "id") or f"F-{index:03d}").strip()
    source = str(pick(row, "source") or source_name).strip()
    evidence = str(pick(row, "evidence") or "").strip()
    status = normalize_status(pick(row, "status"))

    reasons = []
    if cvss is not None:
        reasons.append(f"CVSS {cvss:g}")
    else:
        reasons.append(f"severity {severity} (no CVSS)")
    if epss is not None:
        reasons.append(f"EPSS {epss:.3f}")
    else:
        reasons.append("EPSS unknown")
    if kev:
        reasons.append("KEV")
    if exposed:
        reasons.append("internet-facing")
    if sensitive:
        reasons.append("sensitive data")
    reasons.append(f"confidence {confidence:.2f}")

    return {
        "id": finding_id,
        "title": title,
        "asset": asset,
        "severity": severity,
        "priority": priority,
        "score": score,
        "cvss": cvss,
        "epss": epss,
        "kev": kev,
        "exposed": exposed,
        "sensitive": sensitive,
        "confidence": confidence,
        "cve": cve,
        "status": status,
        "source": source,
        "evidence": evidence,
        "reasons": reasons,
        "missing": [
            name for name, value in (("cvss", cvss), ("epss", epss))
            if value is None
        ] + (["severity"] if severity == "unknown" else []) + [
            name for name in ("kev", "exposed", "sensitive", "confidence")
            if not context_known(pick(row, name), name)
        ],
        "fingerprint": hashlib.sha256(
            "|".join(
                [
                    asset_key(asset),
                    cve,
                    " ".join(title.casefold().split()),
                ]
            ).encode("utf-8")
        ).hexdigest()[:16],
    }


def load_findings(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        raise UserError(f"input not found: {path}")
    text = read_text_bounded(path, encoding="utf-8-sig")
    stripped = text.lstrip()
    if path.suffix.lower() == ".json" or stripped.startswith(("[", "{")):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise UserError(f"invalid JSON: {exc}") from exc
        if isinstance(data, dict):
            for key in ("findings", "results", "vulnerabilities", "items"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
            else:
                data = [data]
        if not isinstance(data, list):
            raise UserError("JSON input must be a list or an object containing a findings list")
        if any(not isinstance(row, dict) for row in data):
            raise UserError("every finding must be a JSON object; refusing to silently drop records")
        return [normalize_finding(row, idx, path.name) for idx, row in enumerate(data, 1)]
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise UserError("CSV input has no header row")
    return [normalize_finding(row, idx, path.name) for idx, row in enumerate(reader, 1)]


def dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: "OrderedDict[Tuple[str, str, str], Dict[str, Any]]" = OrderedDict()
    for item in findings:
        # CVE + asset is the strongest practical dedupe key. If a finding is
        # endpoint-specific, put the full URL/endpoint in `asset` so distinct
        # endpoints stay distinct.
        if item["cve"]:
            key = ("cve", asset_key(item["asset"]), item["cve"])
        else:
            key = ("fingerprint", asset_key(item["asset"]), item["fingerprint"])
        existing = groups.get(key)
        if existing is None:
            groups[key] = item
            continue
        statuses = set(existing.get("status_conflicts", [existing["status"]]))
        statuses.update(item.get("status_conflicts", [item["status"]]))
        sources = list(dict.fromkeys(existing["source"].split("; ") + item["source"].split("; ")))
        evidence = list(dict.fromkeys(existing["evidence"].split("; ") + item["evidence"].split("; ")))
        # Keep the more severe/confident record, but preserve provenance.
        if (item["score"], SEVERITY_RANK[item["severity"]]) > (
            existing["score"], SEVERITY_RANK[existing["severity"]]
        ):
            groups[key] = item
        merged = groups[key]
        merged["source"] = "; ".join(s for s in sources if s)
        merged["evidence"] = "; ".join(e for e in evidence if e)
        if len(statuses) > 1:
            merged["status"] = "unknown"
            merged["status_conflicts"] = sorted(statuses)
            merged["reasons"] = [r for r in merged["reasons"] if not r.startswith("status conflict:")]
            merged["reasons"].append("status conflict: " + ", ".join(sorted(statuses)))
    return list(groups.values())


def render_triage(findings: List[Dict[str, Any]], as_of: date, fmt: str, input_name: str) -> str:
    meta = {
        "tool": f"secops.py {VERSION}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": input_name,
        "as_of": as_of.isoformat(),
        "count": len(findings),
        "formula": "100 * (0.50*impact + 0.20*epss + 0.15*kev + 0.10*exposed + 0.05*sensitive) * confidence",
        "note": "Illustrative priority, not CVSS/SSVC. Unknown inputs are listed in missing; EPSS/flags/unknown impact use 0 and missing confidence uses 0.8 for calculation only. Incomplete records require review; status is not inferred from score.",
    }
    if fmt == "json":
        return json.dumps({**meta, "findings": findings}, ensure_ascii=False, indent=2) + "\n"
    if fmt == "csv":
        fields = [
            "id", "priority", "score", "severity", "cvss", "epss", "kev",
            "exposed", "sensitive", "confidence", "asset", "title", "cve",
            "status", "source", "evidence", "missing",
        ]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for item in findings:
            row = dict(item)
            row["missing"] = ",".join(item["missing"])
            writer.writerow(csv_safe(row))
        return buf.getvalue()

    lines = [
        "# Finding triage",
        "",
        f"- Input: `{md(input_name)}`",
        f"- As of: `{as_of.isoformat()}`",
        f"- Findings: **{len(findings)}**",
        "- Priority formula: `100 * (0.50*impact + 0.20*EPSS + 0.15*KEV + 0.10*exposed + 0.05*sensitive) * confidence`",
        "- Note: priority is an operational aid, not a CVSS/SSVC standard. Missing EPSS is unknown and scored as 0.",
        "- Unknown severity/flags use 0 and missing confidence uses 0.8 for calculation only; review incomplete records. Scores do not determine lifecycle status.",
        "- Note: a CVSS >= 7 / High finding is raised to at least P2 even if its numeric score is lower than a P3 item.",
        "",
        "| Priority | Score | Due | Asset | Finding | CVE | CVSS | EPSS | KEV | Status | Missing | Why |",
        "|---|---:|---|---|---|---|---:|---:|---|---|---|---|",
    ]
    for item in findings:
        due = as_of + timedelta(days=SLA_DAYS[item["priority"]])
        lines.append(
            "| {p} | {score} | {due} | {asset} | {title} | {cve} | {cvss} | {epss} | {kev} | {status} | {missing} | {why} |".format(
                p=item["priority"],
                score=item["score"],
                due=due.isoformat(),
                asset=md(item["asset"]),
                title=md(item["title"]),
                cve=md(item["cve"] or "-"),
                cvss="-" if item["cvss"] is None else f"{item['cvss']:g}",
                epss="-" if item["epss"] is None else f"{item['epss']:.3f}",
                kev="unknown" if "kev" in item["missing"] else ("yes" if item["kev"] else "no"),
                status=item["status"],
                missing=md(", ".join(item["missing"]) or "-"),
                why=md("; ".join(item["reasons"])),
            )
        )
    missing = sum(1 for item in findings if item["missing"])
    lines.extend(
        [
            "",
            f"Incomplete inputs on {missing} finding(s); inspect Missing before acting on illustrative scores.",
            "",
            "## Suggested order",
            "",
            "1. P0/P1 first; check whether a temporary mitigation is available.",
            "2. Confirm `suspected` items before scheduling destructive remediation.",
            "3. Retest with the same evidence after fixing; update status to `fixed`.",
            "",
        ]
    )
    return "\n".join(lines)


def cmd_triage(args: argparse.Namespace) -> int:
    try:
        as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()
    except ValueError as exc:
        raise UserError(f"invalid --as-of date: {args.as_of}") from exc
    findings = load_findings(Path(args.input))
    findings = dedupe_findings(findings)
    findings.sort(key=lambda f: (PRIORITY_RANK[f["priority"]], -f["score"], f["asset"], f["title"]))
    emit(render_triage(findings, as_of, args.format, Path(args.input).name), args.output)
    return 0


# ---------------------------------------------------------------------------
# HTTP command (authorized single-request hardening check)
# ---------------------------------------------------------------------------

@dataclass
class Scope:
    hosts: set = field(default_factory=set)
    wildcards: set = field(default_factory=set)
    networks: list = field(default_factory=list)

    @classmethod
    def from_files(cls, paths: Sequence[str]) -> "Scope":
        scope = cls()
        for raw in paths:
            path = Path(raw)
            if not path.is_file():
                raise UserError(f"scope file not found: {path}")
            for lineno, line in enumerate(read_text_bounded(path, "utf-8-sig").splitlines(), 1):
                entry = line.split("#", 1)[0].strip()
                if not entry:
                    continue
                if "://" in entry:
                    raise UserError(f"{path}:{lineno}: URL scope is unsupported; refusing to broaden an origin/path to a host")
                if "/" in entry and not entry.startswith("*"):
                    try:
                        scope.networks.append(ipaddress.ip_network(entry, strict=True))
                        continue
                    except ValueError as exc:
                        raise UserError(f"{path}:{lineno}: invalid CIDR or nonzero host bits") from exc
                if entry.startswith("*."):
                    suffix = normalize_host(entry[2:])
                    if "." not in suffix or is_ipv4(suffix) or is_ipv6(suffix):
                        raise UserError(f"{path}:{lineno}: invalid wildcard scope")
                    scope.wildcards.add(suffix)
                else:
                    scope.hosts.add(normalize_host(entry))
        if not (scope.hosts or scope.wildcards or scope.networks):
            raise UserError("scope is empty")
        return scope

    def allows_ip(self, ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        if str(ip) in self.hosts:
            return True
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            if self.allows_ip(ip.ipv4_mapped):
                return True
        return any(ip in network for network in self.networks)

    def allows_host(self, host: str) -> bool:
        try:
            host = normalize_host(host)
        except UserError:
            return False
        if host in self.hosts:
            return True
        for suffix in self.wildcards:
            ending = "." + suffix
            if host.endswith(ending):
                prefix = host[: -len(ending)]
                # *.example.com covers one label only: a.example.com, not
                # a.b.example.com. List both patterns if deeper coverage is
                # explicitly intended.
                if prefix and "." not in prefix:
                    return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return self.allows_ip(ip)

    def describe(self) -> str:
        parts = []
        if self.hosts:
            parts.append("hosts=" + ",".join(sorted(self.hosts)))
        if self.wildcards:
            parts.append("wildcards=" + ",".join("*." + w for w in sorted(self.wildcards)))
        if self.networks:
            parts.append("networks=" + ",".join(str(n) for n in self.networks))
        return "; ".join(parts) if parts else "(empty)"


def normalize_host(host: str) -> str:
    if not host or "%" in host or not host.isascii():
        raise UserError("host must be an ASCII hostname or an unscoped IP literal (use punycode for IDNs)")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    host = host.lower().removesuffix(".")
    if len(host) > 253 or re.fullmatch(r"[0-9.]+", host):
        raise UserError("invalid or ambiguous hostname")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in host.split(".")):
        raise UserError("invalid hostname; scope entries must not contain ports or paths")
    return host


def parse_http_url(url: str) -> Tuple[urllib.parse.SplitResult, str, int]:
    if not url or re.search(r"[^\x21-\x7e]|\\", url) or re.search(r"%(?![0-9a-fA-F]{2})", url):
        raise UserError("invalid URL: use ASCII URLs with valid percent escapes and no whitespace/backslashes")
    if re.search(r"[\x00-\x20\x7f]", urllib.parse.unquote(url)):
        raise UserError("URL contains encoded whitespace or control characters")
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise UserError("invalid URL") from exc
    if parts.scheme.lower() not in ("http", "https"):
        raise UserError("only http/https URLs are supported")
    if parts.username is not None or parts.password is not None:
        raise UserError("credentials in the URL are not allowed")
    try:
        host = parts.hostname
        port = parts.port if parts.port is not None else (443 if parts.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise UserError("invalid host/port in URL") from exc
    if not host or not 1 <= port <= 65535:
        raise UserError("URL must have a valid host and port in 1..65535")
    host = normalize_host(host)
    return parts, host, port


def resolve_and_authorize(url: str, scope: Scope) -> List[str]:
    parts, host, port = parse_http_url(url)
    if not scope.allows_host(host):
        raise UserError(f"host not in scope: {host}")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UserError(f"DNS resolution failed for {host}: {exc}") from exc
    addresses = []
    for info in infos:
        ip_text = str(ipaddress.ip_address(info[4][0]))
        if ip_text not in addresses:
            addresses.append(ip_text)
    for ip_text in addresses:
        ip = ipaddress.ip_address(ip_text)
        effective_ip = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
        if (
            not effective_ip.is_global
            or effective_ip.is_reserved
            or effective_ip.is_multicast
        ) and not scope.allows_ip(ip):
            raise UserError(
                f"refusing private/reserved address {ip_text} for {host}; add it to scope explicitly if intended"
            )
    if not addresses or len(addresses) > 32:
        raise UserError("DNS returned no usable addresses or more than 32 addresses")
    return addresses


def connect_pinned(addresses: Sequence[str], port: int, timeout: float) -> socket.socket:
    """Use numeric socket addresses directly; never perform a second DNS lookup."""
    last_error: Optional[OSError] = None
    for address in addresses:
        ip = ipaddress.ip_address(address)
        sock = socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((str(ip), port))
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise UserError(f"connection to authorized addresses failed: {last_error}")


def fetch_once(
    url: str,
    method: str,
    timeout: float,
    context: ssl.SSLContext,
    addresses: Sequence[str],
    tls_info: Optional[Dict[str, Any]] = None,
) -> Tuple[int, Dict[str, str], List[str], bytes]:
    parts, host, port = parse_http_url(url)
    # http.client does not consult proxy environment variables. Its socket is
    # supplied explicitly, preserving Host/SNI and certificate hostname checks.
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    response = None
    try:
        connection.sock = connect_pinned(addresses, port, timeout)
        if parts.scheme.lower() == "https":
            connection.sock = context.wrap_socket(connection.sock, server_hostname=host)
            if tls_info is not None:
                cert = connection.sock.getpeercert() or {}
                cipher = connection.sock.cipher()
                tls_info.update({
                    "version": connection.sock.version(),
                    "cipher": cipher[0] if cipher else None,
                    "verified": context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname,
                    "subject": cert.get("subject"), "issuer": cert.get("issuer"),
                    "notAfter": cert.get("notAfter"), "subjectAltName": cert.get("subjectAltName"),
                })
        target = urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, ""))
        connection.request(method, target, headers={
            "User-Agent": DEFAULT_UA, "Accept": "*/*", "Accept-Encoding": "identity",
            "Connection": "close",
        })
        response = connection.getresponse()
        status = response.status
        headers: Dict[str, str] = {}
        set_cookies: List[str] = []
        for key, value in response.headers.items():
            lk = key.lower()
            if lk == "set-cookie":
                set_cookies.append(value)
            elif lk in headers:
                headers[lk] += ", " + value
            else:
                headers[lk] = value
        body = b""
        if method != "HEAD":
            body = response.read(MAX_HTTP_BYTES)
        return status, headers, set_cookies, body
    finally:
        if response is not None:
            response.close()
        connection.close()


def analyze_headers(
    headers: Dict[str, str],
    url: str,
    status: int,
    set_cookies: Sequence[str],
    tls: Optional[Dict[str, Any]],
) -> List[Dict[str, str]]:
    h = {k.lower(): v for k, v in headers.items()}
    is_https = url.lower().startswith("https://")
    content_type = h.get("content-type", "").split(";", 1)[0].strip().lower()
    browser_document = not content_type or content_type in ("text/html", "application/xhtml+xml")
    findings: List[Dict[str, str]] = []

    def add(check: str, severity: str, evidence: str, recommendation: str) -> None:
        findings.append(
            {
                "check": check,
                "severity": severity,
                "evidence": evidence,
                "recommendation": recommendation,
            }
        )

    if is_https:
        hsts = h.get("strict-transport-security", "")
        if not hsts:
            add(
                "HSTS",
                "medium",
                "Strict-Transport-Security header is absent on an HTTPS response.",
                "Serve HSTS with max-age >= 15552000; add includeSubDomains/preload only after confirming all subdomains are HTTPS.",
            )
        else:
            match = re.search(r"max-age\s*=\s*[\"']?(\d+)", hsts, re.IGNORECASE)
            if not match or int(match.group(1)) < 15552000:
                add(
                    "HSTS max-age",
                    "low",
                    f"Strict-Transport-Security is present but short/invalid: {hsts}",
                    "Use max-age >= 15552000 after validating HTTPS coverage.",
                )

    csp = h.get("content-security-policy", "")
    if browser_document and not csp:
        add(
            "CSP",
            "low",
            "Content-Security-Policy header is absent; this response has no CSP as a defense-in-depth layer.",
            "Deploy a report-only policy first, then enforce a policy that matches the application's actual sources.",
        )
    elif csp:
        lowered = csp.lower()
        if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
            add(
                "CSP unsafe directives",
                "info",
                "CSP contains 'unsafe-inline' or 'unsafe-eval'.",
                "Remove unsafe directives where possible; use nonces/hashes for inline scripts.",
            )

    if h.get("x-content-type-options", "").strip().lower() != "nosniff":
        add(
            "X-Content-Type-Options",
            "low",
            "X-Content-Type-Options: nosniff is absent.",
            "Add 'X-Content-Type-Options: nosniff' to all responses.",
        )

    xfo = h.get("x-frame-options", "")
    frame_ancestors = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp, re.I)
    has_frame_policy = bool(frame_ancestors and frame_ancestors.group(1).strip() != "*")
    if browser_document and xfo.strip().lower() not in ("deny", "sameorigin") and not has_frame_policy:
        add(
            "Frame protection",
            "medium",
            "Neither X-Frame-Options nor CSP frame-ancestors is present.",
            "Set CSP frame-ancestors (preferred) or X-Frame-Options: DENY/SAMEORIGIN.",
        )

    if browser_document and "referrer-policy" not in h:
        add(
            "Referrer-Policy",
            "low",
            "Referrer-Policy is absent.",
            "Use 'Referrer-Policy: strict-origin-when-cross-origin' or a stricter policy.",
        )

    if browser_document and "permissions-policy" not in h:
        add(
            "Permissions-Policy",
            "info",
            "Permissions-Policy is absent.",
            "Disable unused browser features (camera, microphone, geolocation, etc.) explicitly.",
        )

    if browser_document and "cross-origin-opener-policy" not in h:
        add(
            "COOP",
            "info",
            "Cross-Origin-Opener-Policy is absent.",
            "Consider 'Cross-Origin-Opener-Policy: same-origin' where isolation is compatible.",
        )

    if browser_document and "cross-origin-resource-policy" not in h:
        add(
            "CORP",
            "info",
            "Cross-Origin-Resource-Policy is absent.",
            "Consider CORP for sensitive static resources, after validating cross-origin use.",
        )

    disclosure = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "via"):
        if h.get(name):
            disclosure.append(f"{name}: {h[name]}")
    if disclosure:
        add(
            "Version/technology disclosure",
            "low",
            "; ".join(disclosure),
            "Minimize version banners where practical; do not rely on obscurity for security.",
        )

    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao.strip() == "*" and acac == "true":
        add(
            "CORS credentials with wildcard",
            "low",
            "Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true (browsers normally reject this combination).",
            "Remove the wildcard; use an explicit origin allowlist and echo only validated origins. Treat as a misconfiguration unless origin reflection is separately proven.",
        )

    if set_cookies:
        cookie_names = []
        insecure_cookies = []
        httponly_missing = []
        samesite_missing = []
        for raw in set_cookies:
            first = raw.split(";", 1)[0]
            name = first.split("=", 1)[0].strip() or "(unnamed)"
            cookie_names.append(name)
            parts = [part.strip().lower() for part in raw.split(";")[1:]]
            if is_https and "secure" not in parts:
                insecure_cookies.append(name)
            if "httponly" not in parts:
                httponly_missing.append(name)
            if not any(part.startswith("samesite=") for part in parts):
                samesite_missing.append(name)
        if insecure_cookies:
            add(
                "Cookie Secure flag",
                "medium",
                "Cookie(s) without Secure on HTTPS: " + ", ".join(insecure_cookies),
                "Set Secure on all session cookies; never send them over HTTP.",
            )
        if httponly_missing:
            add(
                "Cookie HttpOnly flag",
                "medium",
                "Cookie(s) without HttpOnly: " + ", ".join(httponly_missing),
                "Set HttpOnly on session cookies to reduce XSS impact; update JS that reads them.",
            )
        if samesite_missing:
            add(
                "Cookie SameSite",
                "low",
                "Cookie(s) without SameSite: " + ", ".join(samesite_missing),
                "Set SameSite=Lax/Strict for session cookies; use None+Secure only when cross-site is required.",
            )

    if tls and tls.get("version"):
        version = str(tls["version"])
        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            add(
                "TLS version",
                "high",
                f"Negotiated {version}.",
                "Disable TLS 1.0/1.1 and legacy SSL; require TLS 1.2+ (prefer 1.3).",
            )
        not_after = tls.get("notAfter")
        if not_after:
            try:
                expiry = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(str(not_after)), tz=timezone.utc
                )
                days_left = (expiry - datetime.now(timezone.utc)).total_seconds() / 86400
                if days_left < 0:
                    add(
                        "TLS certificate expiry",
                        "high",
                        f"Certificate expired at {not_after} UTC.",
                        "Renew and deploy the certificate; automate expiry monitoring.",
                    )
                elif days_left <= 30:
                    add(
                        "TLS certificate expiry",
                        "medium",
                        f"Certificate expires in {days_left:.0f} day(s): {not_after} UTC.",
                        "Renew before expiry; add automated monitoring.",
                    )
            except (TypeError, ValueError, OverflowError):
                pass

    if tls and tls.get("error"):
        add(
            "TLS inspection",
            "info",
            f"TLS probe failed: {tls['error']}",
            "Confirm the endpoint is reachable and the certificate chain is valid; this observation does not prove a vulnerability.",
        )

    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda item: (rank.get(item["severity"], 9), item["check"]))
    return findings


def render_http(
    url: str,
    final_url: str,
    status: int,
    headers: Dict[str, str],
    set_cookies: Sequence[str],
    body: bytes,
    redirects: Sequence[str],
    tls: Optional[Dict[str, Any]],
    findings: List[Dict[str, str]],
    addresses: Sequence[str],
    scope: Scope,
    fmt: str,
) -> str:
    url, final_url = redact_text(url), redact_text(final_url)
    redirects = [redact_text(value) for value in redirects]
    tls = redact_data(tls)
    findings = redact_data(findings)
    selected = {}
    for name in (
        "content-type", "content-length", "strict-transport-security",
        "content-security-policy", "x-content-type-options", "x-frame-options",
        "referrer-policy", "permissions-policy", "cross-origin-opener-policy",
        "cross-origin-resource-policy", "access-control-allow-origin",
        "access-control-allow-credentials", "cache-control", "server",
    ):
        if name in headers:
            selected[name] = redact_text(headers[name])
    title = ""
    match = re.search(rb"<title[^>]*>(.*?)</title>", body[:MAX_HTTP_BYTES], re.I | re.S)
    if match:
        title = redact_text(match.group(1).decode("utf-8", errors="replace")).strip()[:200]
    body_hash = hashlib.sha256(body).hexdigest()
    body_label = "first 256 KiB" if len(body) >= MAX_HTTP_BYTES else "full body"

    if fmt == "json":
        payload = {
            "tool": f"secops.py {VERSION}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "url": url,
            "final_url": final_url,
            "status": status,
            "title": title,
            "redirects": list(redirects),
            "resolved_ips": list(addresses),
            "scope": redact_text(scope.describe()),
            "tls": tls,
            "headers": selected,
            "set_cookie_count": len(set_cookies),
            "body_sample_sha256": body_hash,
            "body_sample": body_label,
            "findings": findings,
            "limitations": [
                "Single GET/HEAD request per redirect; not a crawler or vulnerability scanner.",
                "Missing headers are hardening observations, not proof of exploitability.",
                "GET/HEAD may have application side effects; only approved endpoints should be checked.",
                "TLS metadata describes this connection, not all protocols/ciphers supported by the server.",
                "Each hop connects only to validated numeric IPs; proxies from environment variables are ignored.",
                "Scope files constrain hosts/IPs only, not ports, paths, exclusions or authorization time windows.",
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"

    lines = [
        "# Authorized HTTP hardening check",
        "",
        f"- Target: `{md(url)}`",
        f"- Final URL: `{md(final_url)}`",
        f"- Status: `{status}`",
        f"- Title: {md(title) if title else '-'}",
        f"- Resolved IP(s): {', '.join(addresses) if addresses else '-'}",
        f"- Scope: `{md(scope.describe())}`",
        f"- Redirects: {len(redirects)}",
        f"- TLS: {md(tls.get('version')) if tls and tls.get('version') else (md(tls.get('error')) if tls else 'not applicable')}",
        f"- Body sample SHA-256 ({body_label}): `{body_hash}`",
        "",
        "## Observations",
        "",
    ]
    if findings:
        lines.extend(
            [
                "| Severity | Check | Evidence | Recommendation |",
                "|---|---|---|---|",
            ]
        )
        for item in findings:
            lines.append(
                f"| {md(item['severity'])} | {md(item['check'])} | {md(item['evidence'])} | {md(item['recommendation'])} |"
            )
    else:
        lines.append("No obvious missing security headers in this single response.")
    lines.extend(
        [
            "",
            "## Header snapshot",
            "",
            "```http",
        ]
    )
    for key, value in selected.items():
        lines.append(f"{key}: {html.escape(value, quote=False).replace('`', '&#96;')}")
    lines.extend(
        [
            "```",
            "",
            "## Limitations",
            "",
            "- One GET/HEAD request per redirect; not a crawler or vulnerability scanner.",
            "- Missing headers are hardening observations, not proof of exploitability.",
            "- GET/HEAD may have application side effects; only approved endpoints should be checked.",
            "- TLS metadata describes this connection, not all server protocols/ciphers.",
            "- Each hop connects only to validated numeric IPs; environment proxies are ignored.",
            "- Scope files constrain hosts/IPs only, not ports, paths, exclusions or authorization time windows.",
            "",
        ]
    )
    return "\n".join(lines)


def cmd_http(args: argparse.Namespace) -> int:
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 120:
        raise UserError("--timeout must be finite and in (0, 120]")
    if not 0 <= args.max_redirects <= 10:
        raise UserError("--max-redirects must be in 0..10")
    if not math.isfinite(args.delay) or not 0 <= args.delay <= 60:
        raise UserError("--delay must be finite and in [0, 60]")
    if not args.i_have_authorization:
        raise UserError(
            "refusing active request: pass --i-have-authorization only after you have explicit permission"
        )
    if not args.scope_files:
        raise UserError("refusing active request: --scope-file is required")
    scope = Scope.from_files(args.scope_files)
    addresses: List[str] = []
    if args.insecure:
        eprint("warning: --insecure disables TLS verification for this probe")

    context = ssl.create_default_context()
    if args.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    current = args.url
    redirects: List[str] = []
    final_status = 0
    final_headers: Dict[str, str] = {}
    final_cookies: List[str] = []
    final_body = b""
    final_url = current
    tls: Optional[Dict[str, Any]] = None

    for hop in range(args.max_redirects + 1):
        hop_addresses = resolve_and_authorize(current, scope)
        addresses = hop_addresses
        tls = {} if current.lower().startswith("https://") else None
        try:
            status, headers, cookies, body = fetch_once(
                current, args.method, args.timeout, context, hop_addresses, tls
            )
        except (OSError, http.client.HTTPException) as exc:
            raise UserError(f"request failed for {redact_text(current)}: {redact_text(str(exc))}") from exc
        final_status = status
        final_headers = headers
        final_cookies = cookies
        final_body = body
        final_url = current
        location = headers.get("location", "")
        if status in (301, 302, 303, 307, 308) and location and hop < args.max_redirects:
            next_url = urllib.parse.urljoin(current, location)
            next_parts, next_host, _ = parse_http_url(next_url)
            if current.lower().startswith("https://") and next_parts.scheme.lower() == "http":
                raise UserError("refusing HTTPS to HTTP redirect downgrade")
            if not scope.allows_host(next_host):
                raise UserError(f"redirect target not in scope: {redact_text(next_url)}")
            redirects.append(next_url)
            current = next_url
            time.sleep(max(0.0, args.delay))
            continue
        break

    findings = analyze_headers(
        final_headers, final_url, final_status, final_cookies, tls
    )
    emit(
        render_http(
            args.url,
            final_url,
            final_status,
            final_headers,
            final_cookies,
            final_body,
            redirects,
            tls,
            findings,
            addresses,
            scope,
            args.format,
        ),
        args.output,
    )
    return 0


# ---------------------------------------------------------------------------
# Redact command
# ---------------------------------------------------------------------------

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
TOKEN_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("bearer_token", re.compile(r"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]+")),
    ("basic_auth", re.compile(r"(?i)\bBasic[ \t]+[A-Za-z0-9+/=]+")),
    ("cookie", re.compile(r"(?i)\b(?:Cookie|Set-Cookie)[ \t]*:[ \t]*[^\r\n]+")),
]
SECRET_NAMES = {
    "api_key", "apikey", "api-key", "secret", "token", "password", "passwd", "pwd",
    "access_token", "refresh_token", "id_token", "client_secret", "session", "sessionid",
    "secret_access_key", "aws_secret_access_key", "x-amz-signature", "signature", "sig",
}
_SECRET_NAME_PATTERN = "(?:" + "|".join(re.escape(name) for name in sorted(SECRET_NAMES, key=len, reverse=True)) + ")"
GENERIC_SECRET_RE = re.compile(
    r"(?i)((?:\"" + _SECRET_NAME_PATTERN + r"\"|'" + _SECRET_NAME_PATTERN
    + r"'|\b" + _SECRET_NAME_PATTERN + r"\b)\s*[:=]\s*)"
    + r'''("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s,;}&"'<>]+)'''
)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)")
CARD_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d|\.\d)")


def luhn_ok(digits: str) -> bool:
    total = 0
    reverse = digits[::-1]
    for index, char in enumerate(reverse):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def redact_text(text: str, pii: bool = False) -> str:
    def private_key_repl(match: re.Match) -> str:
        newlines = "\n" * match.group(0).count("\n")
        return "[REDACTED:private_key]" + newlines

    text = PRIVATE_KEY_RE.sub(private_key_repl, text)

    def url_repl(match: re.Match) -> str:
        raw = match.group(0)
        try:
            parts = urllib.parse.urlsplit(raw)
            netloc = parts.netloc.rsplit("@", 1)[-1] if "@" in parts.netloc else parts.netloc
            if "@" in parts.netloc:
                netloc = "[REDACTED:userinfo]@" + netloc
            def query_repl(query: str) -> str:
                pairs = re.split(r"([&;])", query)
                for index in range(0, len(pairs), 2):
                    key, sep, value = pairs[index].partition("=")
                    if sep and urllib.parse.unquote_plus(key).lower() in SECRET_NAMES:
                        pairs[index] = key + "=[REDACTED:secret]"
                return "".join(pairs)
            return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path,
                                            query_repl(parts.query), query_repl(parts.fragment)))
        except ValueError:
            # Malformed credential-bearing URLs should not escape redaction.
            return re.sub(r"(?<=//)[^/@\s]+@", "[REDACTED:userinfo]@", raw)

    text = URL_RE.sub(url_repl, text)
    for name, pattern in TOKEN_PATTERNS:
        text = pattern.sub(f"[REDACTED:{name}]", text)

    def secret_repl(match: re.Match) -> str:
        value = match.group(2)
        quote = value[0] if value.startswith(('"', "'")) else ""
        return match.group(1) + quote + "[REDACTED:secret]" + quote

    text = GENERIC_SECRET_RE.sub(
        secret_repl, text
    )
    if pii:
        text = EMAIL_RE.sub("[REDACTED:email]", text)

        def card_repl(match: re.Match) -> str:
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)
            if 13 <= len(digits) <= 19 and luhn_ok(digits):
                return "[REDACTED:payment_card]"
            return raw

        text = CARD_RE.sub(card_repl, text)

        def phone_repl(match: re.Match) -> str:
            digits = re.sub(r"\D", "", match.group(0))
            if 10 <= len(digits) <= 15:
                return "[REDACTED:phone]"
            return match.group(0)

        text = PHONE_RE.sub(phone_repl, text)

        def private_ip_repl(match: re.Match) -> str:
            value = match.group(0)
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                return value
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return "[REDACTED:private_ip]"
            return value

        text = IPV4_RE.sub(private_ip_repl, text)
        text = IPV6_RE.sub(private_ip_repl, text)
    return text


def redact_data(value: Any, pii: bool = False) -> Any:
    """Redact structured output before serialization, keeping it valid JSON."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED:secret]" if str(key).lower() in SECRET_NAMES | {
                "authorization", "proxy-authorization", "cookie", "set-cookie"
            } else redact_data(item, pii)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_data(item, pii) for item in value]
    return redact_text(value, pii) if isinstance(value, str) else value


def cmd_redact(args: argparse.Namespace) -> int:
    if args.input == "-":
        text = read_text_bounded()
    else:
        path = Path(args.input)
        if not path.is_file():
            raise UserError(f"input not found: {path}")
        text = read_text_bounded(path)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        result = redact_text(text, pii=args.pii)
    else:
        result = json.dumps(redact_data(data, pii=args.pii), ensure_ascii=False, indent=2) + "\n"
    emit(result, args.output)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secops.py",
        description="Zero-dependency helpers for authorized security work.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_ioc = sub.add_parser("ioc", help="extract/defang indicators from text")
    p_ioc.add_argument("paths", nargs="*", help="files/directories; omit for stdin")
    p_ioc.add_argument("--format", choices=("md", "json", "csv"), default="md")
    p_ioc.add_argument("--output", help="write output to a file")
    p_ioc.add_argument("--include-emails", action="store_true", help="also extract email addresses")
    p_ioc.add_argument(
        "--no-redact-context",
        action="store_false",
        dest="redact_context",
        help="include raw context (sensitive); indicator extraction still redacts recognized secrets",
    )
    p_ioc.add_argument("--types", nargs="*", help="filter by type: url domain ipv4 ipv6 md5 sha1 sha256 cve email")
    p_ioc.set_defaults(func=cmd_ioc)

    p_hash = sub.add_parser("hash", help="hash files, estimate entropy, identify magic")
    p_hash.add_argument("paths", nargs="+", help="files to hash")
    p_hash.add_argument("--format", choices=("md", "json", "csv"), default="md")
    p_hash.add_argument("--output", help="write output to a file")
    p_hash.add_argument("--sha256", help="compare one file's SHA-256 to this value")
    p_hash.set_defaults(func=cmd_hash)

    p_triage = sub.add_parser("triage", help="normalize/dedupe/prioritize findings")
    p_triage.add_argument("input", help="CSV or JSON findings file")
    p_triage.add_argument("--format", choices=("md", "json", "csv"), default="md")
    p_triage.add_argument("--output", help="write output to a file")
    p_triage.add_argument("--as-of", help="SLA start date, YYYY-MM-DD (default: today)")
    p_triage.set_defaults(func=cmd_triage)

    p_http = sub.add_parser("http", help="authorized single-request HTTP hardening check")
    p_http.add_argument("url", help="http(s) URL to check")
    p_http.add_argument("--scope-file", action="append", dest="scope_files",
                        help="scope file (hosts, *.wildcards, CIDRs); repeatable")
    p_http.add_argument("--i-have-authorization", action="store_true",
                        help="confirm explicit authorization for this target")
    p_http.add_argument("--method", choices=("GET", "HEAD"), default="HEAD")
    p_http.add_argument("--timeout", type=float, default=10.0)
    p_http.add_argument("--max-redirects", type=int, default=5)
    p_http.add_argument("--delay", type=float, default=1.0, help="seconds between redirect hops")
    p_http.add_argument("--insecure", action="store_true", help="disable TLS verification (lab only)")
    p_http.add_argument("--format", choices=("md", "json"), default="md")
    p_http.add_argument("--output", help="write output to a file")
    p_http.set_defaults(func=cmd_http)

    p_redact = sub.add_parser("redact", help="redact secrets/PII from text")
    p_redact.add_argument("input", help="file path or - for stdin")
    p_redact.add_argument("--output", help="write output to a file")
    p_redact.add_argument("--pii", action="store_true", help="also redact emails, phones, cards, private IPv4/IPv6")
    p_redact.set_defaults(func=cmd_redact)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Windows consoles often default to a legacy code page; keep CLI output
    # UTF-8 so Markdown/JSON containing non-ASCII text is not mojibake.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except UserError as exc:
        eprint(f"error: {redact_text(str(exc))}")
        return 2
    except BrokenPipeError:
        return 0
    except (OSError, ValueError, csv.Error) as exc:
        eprint(f"error: {redact_text(str(exc))}")
        return 2
    except KeyboardInterrupt:
        eprint("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
