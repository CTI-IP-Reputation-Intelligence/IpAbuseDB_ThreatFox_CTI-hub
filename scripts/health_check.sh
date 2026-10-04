#!/usr/bin/env bash
set -Eeuo pipefail

config_file="/etc/ddos-cti-stage/stage.env"
state_file="/data/ddos-cti/state/cti_ip_reputation_state.json"
evidence_file="/data/ddos-cti/exports/cti_ip_reputation_current.csv"
feature_file="/data/ddos-cti/features/cti_ip_reputation_features_current.csv"
error_file="/data/ddos-cti/state/cti_ip_reputation_last_error.json"
timer_name="ddos-cti-stage.timer"
install_record="/var/lib/ddos-cti-stage/install-record.txt"
reader_account="${STAGE_READER_ACCOUNT:-}"
reader_group="${STAGE_OUTPUT_GROUP:-}"
failures=0

# Prefer an explicit operator override. Otherwise use the account and group
# recorded by the installer, so any approved reader name works automatically.
if [[ -r "${install_record}" ]]; then
  if [[ -z "${reader_account}" ]]; then
    reader_account="$(awk -F= '$1 == "ReaderAccount" {print substr($0, index($0, "=") + 1); exit}' "${install_record}")"
  fi
  if [[ -z "${reader_group}" ]]; then
    reader_group="$(awk -F= '$1 == "ReaderGroup" {print substr($0, index($0, "=") + 1); exit}' "${install_record}")"
  fi
fi
reader_account="${reader_account:-ml_ai}"
reader_group="${reader_group:-ddos-cti-readers}"

pass() { printf 'PASS: %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; failures=$((failures + 1)); }

if [[ -r "${config_file}" ]]; then
  pass "protected configuration exists"
else
  fail "protected configuration is missing or unreadable"
fi

if systemctl is-active --quiet "${timer_name}"; then
  pass "${timer_name} is active"
else
  fail "${timer_name} is not active"
fi

systemctl list-timers --all "${timer_name}" --no-pager || true

for path in "${state_file}" "${evidence_file}" "${feature_file}"; do
  if [[ -s "${path}" ]]; then
    pass "${path} exists and is non-empty"
  else
    fail "${path} is missing or empty"
  fi
done

for path in "${evidence_file}" "${feature_file}"; do
  if [[ -e "${path}" ]]; then
    actual_group="$(stat -c '%G' "${path}")"
    actual_mode="$(stat -c '%a' "${path}")"
    if [[ "${actual_group}" == "${reader_group}" && "${actual_mode}" == "640" ]]; then
      pass "${path} has group ${reader_group} and mode 0640"
    else
      fail "${path} has group ${actual_group} and mode ${actual_mode}; expected ${reader_group}:0640"
    fi
  fi
done

if id "${reader_account}" >/dev/null 2>&1; then
  if runuser -u "${reader_account}" -- test -r "${feature_file}"; then
    pass "${reader_account} can read the current ML feature file"
  else
    fail "${reader_account} cannot read the current ML feature file"
  fi
else
  warn "reader account ${reader_account} does not exist; read-access test skipped"
fi

if [[ -s "${state_file}" ]]; then
  /opt/ddos-cti-stage/venv/bin/python - "${state_file}" <<'PY'
import json
import sys
from datetime import UTC, datetime

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    state = json.load(handle)
completed = state.get("run_completed_at_utc", "")
status = state.get("status", "unknown")
print(f"State status: {status}")
print(f"Last completed UTC: {completed or 'missing'}")
if completed:
    parsed = datetime.fromisoformat(completed.replace("Z", "+00:00"))
    age_hours = (datetime.now(UTC) - parsed.astimezone(UTC)).total_seconds() / 3600
    print(f"Collection age hours: {age_hours:.1f}")
    if age_hours > 36:
        print("WARNING: collection is older than 36 hours")
PY
fi

if [[ -s "${error_file}" ]]; then
  warn "the last collection attempt failed; redacted diagnostic follows"
  /opt/ddos-cti-stage/venv/bin/python - "${error_file}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    failure = json.load(handle)
print("Failure code:", failure.get("diagnostic_code", "unknown"))
print("Provider:", failure.get("provider", "unknown"))
print("Failed UTC:", failure.get("failed_at_utc", "unknown"))
print("Last success UTC:", failure.get("last_successful_run_utc", "unknown"))
print("Retry at:", failure.get("retry_at") or "not supplied")
print("Message:", failure.get("error", "not supplied"))
PY
  failures=$((failures + 1))
fi

if [[ ${failures} -gt 0 ]]; then
  printf 'Health result: FAIL (%d error(s))\n' "${failures}" >&2
  exit 1
fi

pass "health checks completed"
