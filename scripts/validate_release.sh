#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
pass() { printf '%s: PASS\n' "$*"; }

manifest="release/MANIFEST.txt"
checksums="release/SHA256SUMS"
checksums_copy="release/SHA256SUMS.txt"
[[ -s "${manifest}" && -s "${checksums}" && -s "${checksums_copy}" ]] || \
  fail "release manifest or checksum file is missing/empty."

work_dir="$(mktemp -d)"
trap 'rm -rf -- "${work_dir}"' EXIT

LC_ALL=C sort -u "${manifest}" >"${work_dir}/manifest.sorted"
cmp -s "${manifest}" "${work_dir}/manifest.sorted" || \
  fail "release/MANIFEST.txt must be sorted and contain no duplicate entries."

find . -path './.git' -prune -o -type f \
  ! -path './release/MANIFEST.txt' \
  ! -path './release/SHA256SUMS' \
  ! -path './release/SHA256SUMS.txt' \
  -printf '%P\n' | LC_ALL=C sort >"${work_dir}/actual-files"

if ! cmp -s "${manifest}" "${work_dir}/actual-files"; then
  printf 'Manifest mismatch (lines prefixed < are approved; > are actual):\n' >&2
  diff -u "${manifest}" "${work_dir}/actual-files" >&2 || true
  fail "the source tree does not exactly match release/MANIFEST.txt."
fi
pass "Exact source manifest"

cmp -s "${checksums}" "${checksums_copy}" || \
  fail "SHA256SUMS and SHA256SUMS.txt differ."
awk '{sub(/^[^ ]+  /, ""); print}' "${checksums}" >"${work_dir}/checksum-files"
cmp -s "${manifest}" "${work_dir}/checksum-files" || \
  fail "checksum entries do not exactly match release/MANIFEST.txt."
sha256sum --check --strict "${checksums}"
pass "SHA-256 integrity"

for script in install_ipabusedb_threatfox_cti_hub.sh wrappers/* scripts/*.sh; do
  bash -n "${script}"
done
bash install_ipabusedb_threatfox_cti_hub.sh --help >/dev/null
pass "Shell syntax"

python3 - <<'PY'
from pathlib import Path

for path in (Path("src/collector.py"), Path("src/build_features.py"), Path("tests/test_pipeline.py")):
    compile(path.read_text(encoding="utf-8"), str(path), "exec")
print("Python syntax: PASS")
PY

PYTHONDONTWRITEBYTECODE=1 python3 tests/test_pipeline.py

if find . -mindepth 2 -type d -name .git -print -quit | grep -q .; then
  fail "nested Git metadata is present in the source tree."
fi

if find . -type f \( \
    -name '*.pyc' -o -name '*.log' -o -name '*.env' -o \
    -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.db' -o \
    -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' -o \
    -name '*.kdbx' -o -name '*.csv' -o -name '*.jsonl' -o -name '*.ndjson' -o \
    -name '*.gif' -o -name '*.png' -o -name '*.jpg' -o -name '*.jpeg' -o \
    -name '*.webp' -o -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o \
    -name '*.zip' \) ! -path './config/stage.env.example' ! -path './cti-hub.gif' ! -path './02_threat-intel-merge_zoomed_light.png' -print -quit | grep -q .; then
  fail "generated data, credentials, logs, media, databases, or archives are present."
fi

if grep -RIE --exclude='validate_release.sh' \
  'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY|BEGIN PGP PRIVATE KEY|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}' .; then
  fail "possible secret or private-key material found."
fi

if grep -RIE \
  '(^|[^0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|169\.254\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})([^0-9]|$)' .; then
  fail "private, loopback, or link-local IPv4 literal found."
fi

if grep -RIE '(^|[^0-9A-Fa-f])(fc|fd|fe8|fe9|fea|feb)[0-9A-Fa-f]*:|(^|[^:]):{2}1([^0-9A-Fa-f:]|$)' .; then
  fail "private, loopback, or link-local IPv6 literal found."
fi

if grep -RIE --exclude='validate_release.sh' \
  'ahmedmekkyf13-cloud|CBE|IpAbuseDB_ThreatFox_CTI-hub_development/.git' .; then
  fail "obsolete repository, excluded organization, or development Git path found."
fi

if find . -type f \( -iname '*screenshot*' -o -iname '*alert*' -o -iname '*model*' -o -iname '*backup*' \) -print -quit | grep -q .; then
  fail "excluded screenshot, alert, model, or backup artifact found."
fi

pass "Cleanliness and prohibited-content scans"
printf 'Release validation: PASS\n'
