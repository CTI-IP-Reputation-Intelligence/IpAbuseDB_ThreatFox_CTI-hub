#!/usr/bin/env bash
set -Eeuo pipefail

config_file="/etc/ddos-cti-stage/stage.env"
service_name="ddos-cti-stage.service"
service_group="cti-stage"
action="${1:-}"

usage() {
  cat <<'EOF'
Usage:
  sudo bash update_integration_settings.sh --show
  sudo bash update_integration_settings.sh --abuseipdb-key
  sudo bash update_integration_settings.sh --abuseipdb-url
  sudo bash update_integration_settings.sh --threatfox-url

Secrets are requested with hidden input and are never printed. The protected
configuration is validated and replaced atomically. A collection is not run
automatically because a manual run consumes provider quota.
EOF
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ ${EUID} -eq 0 ]] || fail "run with sudo."
[[ -f "${config_file}" ]] || fail "${config_file} does not exist."

if systemctl is-active --quiet "${service_name}"; then
  fail "${service_name} is running; wait for it to finish and retry."
fi

show_redacted() {
  awk -F= '
    /^[[:space:]]*#/ || NF < 2 {next}
    $1 ~ /KEY|TOKEN|SECRET|PASSWORD|THREATFOX_CSV_URL/ {
      print $1 "=<redacted>"; next
    }
    {print}
  ' "${config_file}"
}

validate_single_line() {
  local value="$1"
  [[ -n "${value}" ]] || fail "the new value cannot be empty."
  [[ "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] || \
    fail "the new value must be one line."
}

upsert() {
  local key="$1"
  local value="$2"
  local source="$3"
  local destination="$4"
  local found=0
  local line

  : >"${destination}"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ "${line}" == "${key}="* ]]; then
      printf '%s=%s\n' "${key}" "${value}" >>"${destination}"
      found=1
    else
      printf '%s\n' "${line}" >>"${destination}"
    fi
  done <"${source}"
  if [[ ${found} -eq 0 ]]; then
    printf '%s=%s\n' "${key}" "${value}" >>"${destination}"
  fi
}

case "${action}" in
  --show)
    show_redacted
    exit 0
    ;;
  --abuseipdb-key)
    key="ABUSEIPDB_API_KEY"
    read -r -s -p "New AbuseIPDB API key: " value
    printf '\n'
    validate_single_line "${value}"
    ;;
  --abuseipdb-url)
    key="ABUSEIPDB_API_URL"
    read -r -p "New AbuseIPDB HTTPS endpoint: " value
    validate_single_line "${value}"
    [[ "${value}" == https://* ]] || fail "the endpoint must start with https://"
    ;;
  --threatfox-url)
    key="THREATFOX_CSV_URL"
    read -r -s -p "New ThreatFox CSV/export HTTPS URL: " value
    printf '\n'
    validate_single_line "${value}"
    [[ "${value}" == https://* ]] || fail "the export URL must start with https://"
    ;;
  *)
    usage
    exit 2
    ;;
esac

config_dir="$(dirname "${config_file}")"
umask 0077
work_one="$(mktemp --tmpdir="${config_dir}" .stage.env.edit.XXXXXX)"
work_two="$(mktemp --tmpdir="${config_dir}" .stage.env.ready.XXXXXX)"
cleanup() {
  rm -f "${work_one}" "${work_two}"
  unset value
}
trap cleanup EXIT

printf -v encoded_value '%q' "${value}"
upsert "${key}" "${encoded_value}" "${config_file}" "${work_one}"
grep -q '^ABUSEIPDB_API_KEY=.' "${work_one}" || fail "ABUSEIPDB_API_KEY would be missing."
grep -q '^THREATFOX_CSV_URL=https://.' "${work_one}" || fail "THREATFOX_CSV_URL would be missing or invalid."

install -o root -g "${service_group}" -m 0640 "${work_one}" "${work_two}"
mv -f "${work_two}" "${config_file}"

printf 'PASS: %s was updated atomically in %s.\n' "${key}" "${config_file}"
printf 'The timer does not need a restart; the next run reads the new value.\n'
printf 'To validate now (consumes provider quota):\n'
printf '  sudo -u cti-stage /usr/local/bin/ddos-cti-collect\n'
printf 'Then inspect:\n'
printf '  sudo journalctl -u ddos-cti-stage.service -n 50 --no-pager\n'
