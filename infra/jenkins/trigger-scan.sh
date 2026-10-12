#!/usr/bin/env bash
# Triggers the argus-scan job from the host.
#
#   ./trigger-scan.sh <APP_NAME> git <GIT_URL> [GIT_REF] [GIT_CREDENTIALS_ID]
#   ./trigger-scan.sh <APP_NAME> local <PATH_UNDER_SOURCES_DIR | /ABSOLUTE/PATH>
#
# An absolute path outside SOURCES_DIR is copied to SOURCES_DIR/.argus-staging, scanned, and removed;
# in that case the script waits until the build finishes.
# Reads JENKINS_ADMIN_ID / JENKINS_ADMIN_PASSWORD / JENKINS_PORT / SOURCES_DIR from .env next to this script.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
set -a
# shellcheck disable=SC1091
[[ -f .env ]] && . ./.env
set +a

usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
(( $# >= 3 )) || usage

app="$1" type="$2"
url="http://127.0.0.1:${JENKINS_PORT:-8080}"
user="${JENKINS_ADMIN_ID:-admin}:${JENKINS_ADMIN_PASSWORD:?set JENKINS_ADMIN_PASSWORD in .env}"
staging=""
jar="$(mktemp)"

cleanup() {
    rm -f -- "$jar"
    # Remove only the folder this run created under .argus-staging.
    if [[ -n "$staging" && "$staging" == */.argus-staging/* && -d "$staging" ]]; then
        rm -rf -- "$staging"
        rmdir --ignore-fail-on-non-empty -- "$(dirname "$staging")"
        echo "removed staging copy: $staging"
    fi
}
trap cleanup EXIT

# Reads a JSON document from stdin and prints the value at a dotted path ("" when missing or null).
json_get() {
    python3 -c '
import json, sys
v = json.load(sys.stdin)
for key in sys.argv[1].split("."):
    v = v.get(key) if isinstance(v, dict) else None
print("" if v is None else v)' "$1"
}

params=(--data-urlencode "APP_NAME=$app" --data-urlencode "SOURCE_TYPE=$type")
case "$type" in
    git)
        params+=(--data-urlencode "GIT_URL=$3" --data-urlencode "GIT_REF=${4:-}"
                 --data-urlencode "GIT_CREDENTIALS_ID=${5:-}") ;;
    local)
        local_path="$3"
        if [[ "$local_path" == /* ]]; then
            sources_root="$(realpath "${SOURCES_DIR:-./sources}")"
            src="$(realpath -e "$local_path")" || { echo "local source not found: $local_path" >&2; exit 1; }
            [[ -d "$src" ]] || { echo "not a directory: $src" >&2; exit 1; }
            if [[ "$src" == "$sources_root" || "$src" == "$sources_root/"* ]]; then
                local_path="${src#"$sources_root"}"
                local_path="${local_path#/}"
            else
                # The container only sees SOURCES_DIR, so copy the source there for this run.
                local_path=".argus-staging/$app-$(date +%Y%m%d-%H%M%S)-$$"
                staging="$sources_root/$local_path"
                mkdir -p "$staging"
                echo "copying $src -> $staging"
                tar -C "$src" --exclude='./build' --exclude='./target' --exclude='./.gradle' \
                    --exclude='./node_modules' -cf - . | tar -C "$staging" -xf -
            fi
        fi
        params+=(--data-urlencode "LOCAL_PATH=$local_path")
        [[ -n "$staging" ]] && params+=(--data-urlencode "SOURCE_LABEL=local:$src")
        ;;
    *) usage ;;
esac

crumb_json="$(curl -fsS -u "$user" -c "$jar" "$url/crumbIssuer/api/json")"
crumb="$(json_get crumb <<<"$crumb_json")"
crumb_field="$(json_get crumbRequestField <<<"$crumb_json")"

# Parse the Location header ourselves: %header{} in -w needs curl >= 7.84, which older distros lack.
headers="$(curl -fsS -u "$user" -b "$jar" -H "$crumb_field: $crumb" -X POST \
    "$url/job/argus-scan/buildWithParameters" "${params[@]}" -o /dev/null -D -)"
queue_url="$(tr -d '\r' <<<"$headers" | sed -n 's/^[Ll]ocation: *//p' | tail -n 1)"
echo "queued: ${queue_url:-unknown}"
echo "results: ${REPORTS_DIR:-./reports}/$app/latest/"

# Without a staging copy there is nothing to clean up, so return immediately.
[[ -n "$staging" ]] || exit 0
[[ -n "$queue_url" ]] || { echo "could not find the queued build; staging copy is removed now" >&2; exit 1; }

echo "waiting for the build to finish (the staging copy is removed afterwards)..."
build_url=""
until [[ -n "$build_url" ]]; do
    sleep 2
    build_url="$(curl -fsS -u "$user" "${queue_url%/}/api/json" | json_get executable.url)"
done
echo "build: $build_url"
result=""
until [[ -n "$result" ]]; do
    sleep 5
    result="$(curl -fsS -u "$user" "${build_url%/}/api/json?tree=result" | json_get result)"
done
echo "result: $result"
[[ "$result" == SUCCESS || "$result" == UNSTABLE ]]
