#!/usr/bin/env bash
# Triggers the argus-scan job from the host.
#
#   ./trigger-scan.sh <APP_NAME> git <GIT_URL> [GIT_REF] [GIT_CREDENTIALS_ID]
#   ./trigger-scan.sh <APP_NAME> local <PATH_UNDER_SOURCES_DIR>
#
# Reads JENKINS_ADMIN_ID / JENKINS_ADMIN_PASSWORD / JENKINS_PORT from .env next to this script.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
set -a
# shellcheck disable=SC1091
[[ -f .env ]] && . ./.env
set +a

usage() { sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
(( $# >= 3 )) || usage

app="$1" type="$2"
params=(--data-urlencode "APP_NAME=$app" --data-urlencode "SOURCE_TYPE=$type")
case "$type" in
    git)
        params+=(--data-urlencode "GIT_URL=$3" --data-urlencode "GIT_REF=${4:-}"
                 --data-urlencode "GIT_CREDENTIALS_ID=${5:-}") ;;
    local)
        params+=(--data-urlencode "LOCAL_PATH=$3") ;;
    *) usage ;;
esac

url="http://127.0.0.1:${JENKINS_PORT:-8080}"
user="${JENKINS_ADMIN_ID:-admin}:${JENKINS_ADMIN_PASSWORD:?set JENKINS_ADMIN_PASSWORD in .env}"
jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT

crumb="$(curl -fsS -u "$user" -c "$jar" "$url/crumbIssuer/api/json" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["crumbRequestField"] + ":" + d["crumb"])')"

curl -fsS -u "$user" -b "$jar" -H "$crumb" -X POST "$url/job/argus-scan/buildWithParameters" \
    "${params[@]}" -o /dev/null -w 'queued (HTTP %{http_code})\n'
echo "results: ${REPORTS_DIR:-./reports}/$app/latest/"
