#!/usr/bin/env bash
# Copyright © 2026 Ahmed Mekky. All rights reserved.
# One-command installer for the standalone IpAbuseDB_ThreatFox_CTI hub.

set -Eeuo pipefail

readonly PRODUCT_NAME="IpAbuseDB_ThreatFox_CTI hub"
readonly INSTALL_VERSION="1.0.0"
readonly APP_ROOT="/opt/ddos-cti-stage"
readonly CONFIG_ROOT="/etc/ddos-cti-stage"
readonly DATA_ROOT="/data/ddos-cti"
readonly SERVICE_USER="cti-stage"
readonly SERVICE_GROUP="cti-stage"
readonly READER_GROUP="ddos-cti-readers"
readonly SERVICE_NAME="ddos-cti-stage.service"
readonly TIMER_NAME="ddos-cti-stage.timer"
readonly DEFAULT_READER="ml_ai"
readonly DEFAULT_ABUSE_URL="https://api.abuseipdb.com/api/v2/blacklist"

source_dir=""
validate_only=""
work_dir=""
backup_dir=""
timer_was_active=0

info() { printf '[INFO] %s\n' "$*"; }
pass() { printf '[PASS] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  sudo bash install_ipabusedb_threatfox_cti_hub.sh
  sudo bash install_ipabusedb_threatfox_cti_hub.sh --source-dir /path/to/source
  bash install_ipabusedb_threatfox_cti_hub.sh --validate-source /path/to/source

Options:
  --source-dir DIR       Install from an extracted release other than the
                         directory containing this installer.
  --validate-source DIR  Run offline source integrity, syntax, and synthetic
                         tests only. No root access or machine change is made.
  --help                 Show this help.

Normal installation uses the verified local repository or release archive. It
asks for provider settings and the ML reader account before making changes.
Secret inputs are hidden and are never written to the source tree.
EOF
}

cleanup() {
  local status=$?
  if [[ -n "${work_dir}" && -d "${work_dir}" ]]; then
    rm -rf -- "${work_dir}"
  fi
  unset abuseipdb_key threatfox_csv_url
  if [[ ${status} -ne 0 ]]; then
    printf '\n[FAILED] Installation stopped safely.\n' >&2
    printf 'The daily timer was not newly enabled after this failure.\n' >&2
    if [[ -n "${backup_dir}" && -d "${backup_dir}" ]]; then
      printf 'Pre-change files, if any, are in: %s\n' "${backup_dir}" >&2
    fi
    printf 'Review: sudo journalctl -u %s -n 80 --no-pager\n' "${SERVICE_NAME}" >&2
  fi
  return "${status}"
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-dir)
      [[ $# -ge 2 ]] || fail "--source-dir requires a directory."
      source_dir="$2"; shift 2 ;;
    --validate-source)
      [[ $# -ge 2 ]] || fail "--validate-source requires a directory."
      validate_only="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done

validate_https() {
  local label="$1" value="$2"
  [[ "${value}" == https://* ]] || fail "${label} must start with https://"
  [[ "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] || \
    fail "${label} must be one line."
}

validate_account_name() {
  local value="$1"
  [[ "${value}" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]] || \
    fail "Linux reader account must match ^[a-z_][a-z0-9_-]{0,30}$"
}

validate_source_tree() {
  local root="$1"
  local required=(
    VERSION requirements.txt src/collector.py src/build_features.py
    wrappers/ddos-cti-collect wrappers/ddos-cti-build-features
    systemd/ddos-cti-stage.service systemd/ddos-cti-stage.timer
    systemd/ddos-cti-stage.service.d/features.conf
    scripts/health_check.sh scripts/update_integration_settings.sh
    scripts/validate_release.sh tests/test_pipeline.py release/SHA256SUMS
  )
  local path

  [[ -d "${root}" ]] || fail "Source directory does not exist: ${root}"
  for path in "${required[@]}"; do
    [[ -f "${root}/${path}" ]] || fail "Release is missing required file: ${path}"
  done

  info "Verifying release checksums."
  (cd "${root}" && sha256sum --check --strict release/SHA256SUMS)
  info "Running offline syntax, cleanliness, and synthetic-pipeline tests."
  (cd "${root}" && bash scripts/validate_release.sh)
  pass "Source integrity and offline acceptance checks passed."
}

if [[ -n "${validate_only}" ]]; then
  [[ -z "${source_dir}" ]] || fail "Use either --validate-source or --source-dir, not both."
  validate_source_tree "$(cd "${validate_only}" && pwd)"
  exit 0
fi

if [[ -z "${source_dir}" ]]; then
  source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  source_dir="$(cd "${source_dir}" && pwd)"
fi

[[ ${EUID} -eq 0 ]] || fail "Run the installer with sudo."
[[ -t 0 || -n "${INSTALL_CONFIRM:-}" ]] || \
  fail "An interactive terminal is required unless approved automation variables are supplied."

read_visible() {
  local prompt="$1" default="$2" variable="$3" answer
  if [[ -n "${!variable:-}" ]]; then
    answer="${!variable}"
  else
    read -r -p "${prompt} [${default}]: " answer
    answer="${answer:-${default}}"
  fi
  printf -v "${variable}" '%s' "${answer}"
}

read_secret() {
  local prompt="$1" variable="$2" answer
  if [[ -n "${!variable:-}" ]]; then
    answer="${!variable}"
  else
    read -r -s -p "${prompt}: " answer
    printf '\n'
  fi
  [[ -n "${answer}" ]] || fail "${prompt} cannot be empty."
  [[ "${answer}" != *$'\n'* && "${answer}" != *$'\r'* ]] || \
    fail "${prompt} must be one line."
  printf -v "${variable}" '%s' "${answer}"
}

printf '\n%s %s installer\n' "${PRODUCT_NAME}" "${INSTALL_VERSION}"
printf 'This installs only the CTI collection/staging layer and DDoS-ML lookup.\n'
printf 'It does not install OpenCTI, Grafana, Docker, or the DDoS-ML model.\n\n'

read_secret "AbuseIPDB API key" abuseipdb_key
read_secret "ThreatFox CSV/export HTTPS URL" threatfox_csv_url
validate_https "ThreatFox CSV/export URL" "${threatfox_csv_url}"
read_visible "Linux account that will read the ML CSV" "${DEFAULT_READER}" reader_account
validate_account_name "${reader_account}"

printf '\nInstallation summary (secrets are never displayed)\n'
printf '  Source              : %s\n' "${source_dir}"
printf '  AbuseIPDB API key   : <provided>\n'
printf '  ThreatFox feed URL  : <provided; hidden>\n'
printf '  ML reader account   : %s\n' "${reader_account}"
printf '  Daily schedule      : 02:15 server-local time\n'
printf '  Retention           : 90 days\n'
printf '  AbuseIPDB filter    : IPv4, score 100, maximum 1,000 rows\n'
printf '  ThreatFox filter    : ip:port records, deduplicated by IP\n'
printf '  First live run      : yes (normally one request per provider)\n\n'

if [[ "${INSTALL_CONFIRM:-}" == "yes" ]]; then
  confirmation="INSTALL"
else
  read -r -p "Type INSTALL to continue: " confirmation
fi
[[ "${confirmation}" == "INSTALL" ]] || fail "Installation cancelled."

info "Running clean-Ubuntu preflight checks."
[[ -r /etc/os-release ]] || fail "Cannot identify the operating system."
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || fail "Supported operating system is Ubuntu; detected ${ID:-unknown}."
case "${VERSION_ID:-}" in
  22.04|24.04|26.04) ;;
  *) warn "Ubuntu ${VERSION_ID:-unknown} is not in the validated 22.04/24.04 set." ;;
esac
command -v systemctl >/dev/null || fail "systemd is required."
available_kb="$(df -Pk /opt | awk 'NR==2 {print $4}')"
[[ "${available_kb}" =~ ^[0-9]+$ && ${available_kb} -ge 1048576 ]] || \
  fail "At least 1 GiB free space is required on the /opt filesystem."
pass "OS, systemd, and disk-space preflight passed."

info "Installing the minimal approved runtime packages."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl python3 python3-venv
pass "Required runtime packages are present."

work_dir="$(mktemp -d /tmp/ipabusedb-threatfox-install.XXXXXX)"
install -d -m 0700 "${work_dir}/source"
info "Copying the supplied local source into a private work directory."
cp -a "${source_dir}/." "${work_dir}/source/"

validate_source_tree "${work_dir}/source"

info "Checking external HTTPS reachability before machine changes."
curl --silent --show-error --head --max-time 20 https://api.abuseipdb.com/ >/dev/null || \
  fail "Cannot reach AbuseIPDB over HTTPS. Check DNS, proxy, firewall, and system time."
threatfox_origin="$(python3 - "${threatfox_csv_url}" <<'PY'
from urllib.parse import urlsplit
import sys

parts = urlsplit(sys.argv[1])
print(f"{parts.scheme}://{parts.netloc}")
PY
)"
curl --silent --show-error --head --max-time 20 "${threatfox_origin}/" >/dev/null || \
  fail "Cannot reach the ThreatFox feed host over HTTPS. Check DNS, proxy, firewall, and system time."
unset threatfox_origin
pass "External HTTPS reachability checks passed."

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="/var/backups/ipabusedb-threatfox-cti-hub/${timestamp}"
install -d -o root -g root -m 0700 "${backup_dir}"
for existing in "${APP_ROOT}/app" "${CONFIG_ROOT}/stage.env" \
  "/etc/systemd/system/${SERVICE_NAME}" "/etc/systemd/system/${TIMER_NAME}"; do
  if [[ -e "${existing}" ]]; then
    cp -a --parents "${existing}" "${backup_dir}/"
  fi
done

if systemctl is-active --quiet "${SERVICE_NAME}"; then
  fail "${SERVICE_NAME} is currently running; wait for it to finish and rerun."
fi
if systemctl is-active --quiet "${TIMER_NAME}"; then
  timer_was_active=1
fi
systemctl disable --now "${TIMER_NAME}" >/dev/null 2>&1 || true

info "Creating restricted service and ML-reader identities."
getent group "${SERVICE_GROUP}" >/dev/null || groupadd --system "${SERVICE_GROUP}"
id "${SERVICE_USER}" >/dev/null 2>&1 || \
  useradd --system --gid "${SERVICE_GROUP}" --home-dir "${APP_ROOT}" \
    --shell /usr/sbin/nologin --no-create-home "${SERVICE_USER}"
getent group "${READER_GROUP}" >/dev/null || groupadd --system "${READER_GROUP}"
id "${reader_account}" >/dev/null 2>&1 || \
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin \
    --no-create-home "${reader_account}"
usermod -a -G "${READER_GROUP}" "${SERVICE_USER}"
usermod -a -G "${READER_GROUP}" "${reader_account}"
pass "Service account ${SERVICE_USER} and reader account ${reader_account} are ready."

info "Installing application, protected configuration, and data directories."
install -d -o root -g "${SERVICE_GROUP}" -m 0750 "${APP_ROOT}" "${APP_ROOT}/app"
install -o root -g "${SERVICE_GROUP}" -m 0640 \
  "${work_dir}/source/src/collector.py" "${APP_ROOT}/app/collector.py"
install -o root -g "${SERVICE_GROUP}" -m 0640 \
  "${work_dir}/source/src/build_features.py" "${APP_ROOT}/app/build_features.py"

python3 -m venv "${APP_ROOT}/venv"
"${APP_ROOT}/venv/bin/python" -m pip install --disable-pip-version-check \
  --requirement "${work_dir}/source/requirements.txt"
chown -R root:"${SERVICE_GROUP}" "${APP_ROOT}"
chmod -R o-rwx "${APP_ROOT}"

install -d -o root -g "${SERVICE_GROUP}" -m 0750 "${CONFIG_ROOT}"
config_temp="$(mktemp "${CONFIG_ROOT}/.stage.env.XXXXXX")"
chmod 0600 "${config_temp}"
{
  printf '# Generated by %s %s on %s\n' "${PRODUCT_NAME}" "${INSTALL_VERSION}" "${timestamp}"
  printf 'ABUSEIPDB_API_KEY=%q\n' "${abuseipdb_key}"
  printf 'ABUSEIPDB_API_URL=%q\n' "${DEFAULT_ABUSE_URL}"
  printf 'ABUSEIPDB_LIMIT=1000\nABUSEIPDB_SCORE=100\nABUSEIPDB_IPVERSION=4\n'
  printf 'THREATFOX_CSV_URL=%q\n' "${threatfox_csv_url}"
  printf 'THREATFOX_IOC_TO_IMPORT=ip:port\nTHREATFOX_IMPORT_OFFLINE=true\nTHREATFOX_INTERVAL=1\n'
  printf 'STAGE_MAX_DOWNLOAD_BYTES=536870912\nSTAGE_CONNECT_TIMEOUT=15\nSTAGE_READ_TIMEOUT=180\n'
  printf 'STAGE_OUTPUT_GROUP=%q\n' "${READER_GROUP}"
} >"${config_temp}"
chown root:"${SERVICE_GROUP}" "${config_temp}"
chmod 0640 "${config_temp}"
mv -f "${config_temp}" "${CONFIG_ROOT}/stage.env"
unset abuseipdb_key threatfox_csv_url

install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0750 \
  "${DATA_ROOT}/raw/abuseipdb" "${DATA_ROOT}/raw/threatfox" "${DATA_ROOT}/state"
install -d -o "${SERVICE_USER}" -g "${READER_GROUP}" -m 2750 \
  "${DATA_ROOT}/exports" "${DATA_ROOT}/exports/archive" \
  "${DATA_ROOT}/features" "${DATA_ROOT}/features/archive"

install -o root -g root -m 0755 "${work_dir}/source/wrappers/ddos-cti-collect" \
  /usr/local/bin/ddos-cti-collect
install -o root -g root -m 0755 "${work_dir}/source/wrappers/ddos-cti-build-features" \
  /usr/local/bin/ddos-cti-build-features
install -o root -g root -m 0755 "${work_dir}/source/scripts/health_check.sh" \
  /usr/local/bin/ddos-cti-health
install -o root -g root -m 0755 "${work_dir}/source/scripts/update_integration_settings.sh" \
  /usr/local/bin/ddos-cti-update-settings

install -o root -g root -m 0644 "${work_dir}/source/systemd/${SERVICE_NAME}" \
  "/etc/systemd/system/${SERVICE_NAME}"
install -o root -g root -m 0644 "${work_dir}/source/systemd/${TIMER_NAME}" \
  "/etc/systemd/system/${TIMER_NAME}"
install -d -o root -g root -m 0755 "/etc/systemd/system/${SERVICE_NAME}.d"
install -o root -g root -m 0644 \
  "${work_dir}/source/systemd/${SERVICE_NAME}.d/features.conf" \
  "/etc/systemd/system/${SERVICE_NAME}.d/features.conf"

install -d -o root -g root -m 0700 /var/lib/ddos-cti-stage
cat >"/var/lib/ddos-cti-stage/install-record.txt" <<EOF
Product=${PRODUCT_NAME}
Version=${INSTALL_VERSION}
InstalledAtUTC=${timestamp}
Source=${source_dir}
SourceVersion=${INSTALL_VERSION}
ReaderAccount=${reader_account}
ReaderGroup=${READER_GROUP}
Schedule=02:15 server-local daily
RetentionDays=90
GitHubAuthentication=not retained; source was supplied locally
CredentialReviewDueUTC=$(date -u -d '+90 days' +%Y-%m-%dT00:00:00Z)
EOF
chmod 0600 /var/lib/ddos-cti-stage/install-record.txt
systemctl daemon-reload
pass "Files and systemd units are installed."

info "Running the controlled first live collection and ML feature build."
if ! systemctl start "${SERVICE_NAME}"; then
  systemctl disable --now "${TIMER_NAME}" >/dev/null 2>&1 || true
  journalctl -u "${SERVICE_NAME}" -n 80 --no-pager >&2 || true
  fail "First collection failed. The timer remains disabled; correct connectivity or credentials, then rerun the installer."
fi

for output in \
  "${DATA_ROOT}/exports/cti_ip_reputation_current.csv" \
  "${DATA_ROOT}/features/cti_ip_reputation_features_current.csv"; do
  [[ -s "${output}" ]] || fail "Expected output is missing or empty: ${output}"
  [[ "$(stat -c '%G:%a' "${output}")" == "${READER_GROUP}:640" ]] || \
    fail "Output ownership check failed for ${output}"
done
runuser -u "${reader_account}" -- test -r \
  "${DATA_ROOT}/features/cti_ip_reputation_features_current.csv" || \
  fail "Reader account ${reader_account} cannot read the ML feature CSV."

systemctl enable --now "${TIMER_NAME}"
STAGE_READER_ACCOUNT="${reader_account}" STAGE_OUTPUT_GROUP="${READER_GROUP}" \
  /usr/local/bin/ddos-cti-health

printf '\n[SUCCESS] %s %s is installed and operational.\n' "${PRODUCT_NAME}" "${INSTALL_VERSION}"
printf 'ML input       : %s/features/cti_ip_reputation_features_current.csv\n' "${DATA_ROOT}"
printf 'Evidence CSV   : %s/exports/cti_ip_reputation_current.csv\n' "${DATA_ROOT}"
printf 'Daily schedule : 02:15 server-local time (persistent timer)\n'
printf 'Health check   : sudo /usr/local/bin/ddos-cti-health\n'
printf 'Timer check    : sudo systemctl list-timers --all %s --no-pager\n' "${TIMER_NAME}"
printf 'Job logs       : sudo journalctl -u %s -n 80 --no-pager\n' "${SERVICE_NAME}"
printf 'Rotate secrets : sudo /usr/local/bin/ddos-cti-update-settings --show\n'
printf 'Install record : /var/lib/ddos-cti-stage/install-record.txt\n'
printf 'Backup created : %s\n' "${backup_dir}"
