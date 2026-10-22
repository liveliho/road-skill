#!/usr/bin/env python3
"""Build an allowlisted, reproducible installable skill archive; stdlib only."""

import argparse
import ast
import hashlib
import re
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
PACKAGED_FILES = (
    "SKILL.md", "README.md", ".gitignore",
    "scripts/secops.py", "scripts/test_secops.py", "scripts/test_security.py",
    "assets/finding-template.md", "assets/report-template.md", "assets/scope-example.txt",
    "assets/scope-template.md", "assets/triage-example.csv",
    "references/00-scope-and-rules.md", "references/01-recon-osint.md",
    "references/02-web-api.md", "references/03-vuln-triage.md",
    "references/04-network-pcap.md", "references/05-malware-binary.md",
    "references/06-incident-response.md", "references/07-detection-engineering.md",
    "references/08-cloud-container.md", "references/09-secure-code-supply-chain.md",
    "references/10-reporting.md", "references/frameworks.md", "references/sources.md",
)


def package_bytes(skill_dir):
    root = Path(skill_dir).resolve()
    contents = {}
    for name in PACKAGED_FILES:
        path = root / name
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise ValueError(f"missing file or path outside skill: {name}")
        for part in (path, *path.parents):
            if part == root:
                break
            if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
                raise ValueError(f"linked files/directories are not allowed in releases: {name}")
        contents[name] = path.read_bytes()
        if name.endswith(".py"):
            ast.parse(contents[name].decode("utf-8"), filename=name)
    skill = contents["SKILL.md"].decode("utf-8")
    if not skill.startswith("---\nname: cybersecurity-ops\ndescription: "):
        raise ValueError("unexpected skill frontmatter")
    for reference in re.findall(r"(?:references|scripts|assets)/[A-Za-z0-9][A-Za-z0-9._/-]*", skill):
        if reference not in contents:
            raise ValueError(f"entrypoint references unpackaged resource: {reference}")
    tree = ast.parse(contents["scripts/secops.py"].decode("utf-8"))
    version = next((node.value.value for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "VERSION" for target in node.targets)
                    and isinstance(node.value, ast.Constant)), None)
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("invalid release version")
    return contents, version


def build(skill_dir, output_dir):
    contents, version = package_bytes(skill_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"cybersecurity-ops-{version}.zip"
    with ZipFile(archive, "w", compression=ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, data in sorted(contents.items()):
            info = ZipInfo("cybersecurity-ops/" + name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = ZIP_DEFLATED
            bundle.writestr(info, data, compresslevel=9)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".zip.sha256").write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    return archive


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    result = build(ROOT / ".dsh/skills/cybersecurity-ops", args.output_dir)
    print(result)
