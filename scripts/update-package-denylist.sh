#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/DataDog/malicious-software-packages-dataset.git"
TARGET_DIR="src/generated"
EXPECTED_COMMIT="${WSH_DENYLIST_REPO_COMMIT:-}"

mkdir -p "$TARGET_DIR"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

repo_dir="$tmpdir/malicious-software-packages-dataset"

git clone --depth 1 "$REPO_URL" "$repo_dir"
if [[ -z "$EXPECTED_COMMIT" ]]; then
  echo "error: set WSH_DENYLIST_REPO_COMMIT to a trusted commit SHA before updating denylists" >&2
  exit 1
fi
(
  cd "$repo_dir"
  git fetch --depth 1 origin "$EXPECTED_COMMIT"
  git checkout --detach "$EXPECTED_COMMIT"
  actual_commit="$(git rev-parse HEAD)"
  if [[ "$actual_commit" != "$EXPECTED_COMMIT" ]]; then
    echo "error: denylist repo commit mismatch (expected $EXPECTED_COMMIT, got $actual_commit)" >&2
    exit 1
  fi
)

python3 - <<'PY' "$repo_dir" "$TARGET_DIR"
import csv
import json
import os
import re
import sys
from pathlib import Path

repo = Path(sys.argv[1])
out_dir = Path(sys.argv[2])

PACKAGE_KEYS = ("package", "package_name", "name")
ECOSYSTEM_KEYS = (
    "ecosystem",
    "registry",
    "package_manager",
    "manager",
    "source_registry",
)

ECOSYSTEM_ALIASES = {
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "javascript": "npm",
    "pypi": "pypi",
    "pip": "pypi",
    "python": "pypi",
    "cargo": "cargo",
    "crates": "cargo",
    "crates-io": "cargo",
    "crates_io": "cargo",
    "go": "go",
    "golang": "go",
    "gomod": "go",
    "modules": "go",
}

lists = {
    "npm": set(),
    "pypi": set(),
    "cargo": set(),
    "go": set(),
}

PAIR_RE = re.compile(
    r"(?i)(npm|nodejs|pypi|pip|cargo|crates[-_ ]?io|go|golang|gomod|modules|rubygems)[^a-z0-9_@./-]+([@a-z0-9_./-]+)"
)


def normalize_ecosystem(value: str):
    key = value.strip().lower().replace(" ", "").replace("_", "-")
    return ECOSYSTEM_ALIASES.get(key)


def add(ecosystem, package):
    if not ecosystem or not package:
        return
    pkg = package.strip().lower()
    if not pkg:
        return
    if ecosystem not in lists:
        return
    lists[ecosystem].add(pkg)


def walk_json(value, inherited_ecosystem=None):
    if isinstance(value, dict):
        ecosystem = inherited_ecosystem
        for k, v in value.items():
            if k in ECOSYSTEM_KEYS and isinstance(v, str):
                eco = normalize_ecosystem(v)
                if eco:
                    ecosystem = eco
                    break

        package = None
        for k in PACKAGE_KEYS:
            if k in value and isinstance(value[k], str):
                package = value[k]
                break
        if ecosystem and package:
            add(ecosystem, package)

        for v in value.values():
            walk_json(v, ecosystem)
    elif isinstance(value, list):
        for item in value:
            walk_json(item, inherited_ecosystem)


def try_parse_json(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return False
    walk_json(payload)
    return True


def try_parse_jsonl(path: Path):
    success = False
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            walk_json(payload)
            success = True
    return success


def try_parse_csv(path: Path):
    with path.open(encoding="utf-8", errors="ignore", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            return
        headers = {h.strip().lower(): h for h in reader.fieldnames if h}
        pkg_field = next((headers.get(k) for k in PACKAGE_KEYS if headers.get(k)), None)
        eco_field = next((headers.get(k) for k in ECOSYSTEM_KEYS if headers.get(k)), None)
        if not pkg_field or not eco_field:
            return
        for row in reader:
            ecosystem = normalize_ecosystem(str(row.get(eco_field, "")))
            package = str(row.get(pkg_field, ""))
            add(ecosystem, package)


def regex_fallback(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")
    for match in PAIR_RE.finditer(text):
        ecosystem = normalize_ecosystem(match.group(1))
        package = match.group(2)
        add(ecosystem, package)


for path in repo.rglob("*"):
    if not path.is_file():
        continue
    if ".git" in path.parts:
        continue

    suffix = path.suffix.lower()
    if suffix in {".json"}:
        if not try_parse_json(path):
            try_parse_jsonl(path)
    elif suffix in {".jsonl", ".ndjson"}:
        try_parse_jsonl(path)
    elif suffix in {".csv", ".tsv"}:
        try_parse_csv(path)
    elif suffix in {".txt", ".md", ".yml", ".yaml"}:
        regex_fallback(path)

for ecosystem in ("npm", "pypi", "cargo", "go"):
    output_path = out_dir / f"{ecosystem}_denylist.txt"
    entries = sorted(lists[ecosystem])
    output_path.write_text("\n".join(entries) + ("\n" if entries else ""), encoding="utf-8")
    print(f"wrote {output_path} ({len(entries)} entries)")
PY
