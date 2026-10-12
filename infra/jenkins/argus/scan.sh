#!/usr/bin/env bash
# Runs every scanner against one application and writes SARIF/SBOM files to
# $ARGUS_REPORTS_DIR/<APP_NAME>/<timestamp>/.
#
# Exit codes: 0 = all steps succeeded or were skipped, 1 = source could not be prepared,
#             2 = at least one scanner failed (other results are still written).
set -euo pipefail

ARGUS_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_ROOT="${ARGUS_REPORTS_DIR:-/reports}"
SOURCES_ROOT="${ARGUS_SOURCES_DIR:-/sources}"
SEMGREP_CONFIGS="${SEMGREP_CONFIGS:-p/java}"
PMD_RULESET="${PMD_RULESET:-rulesets/java/quickstart.xml}"

APP_NAME="${APP_NAME:-}"
SOURCE_TYPE="${SOURCE_TYPE:-git}"
GIT_URL="${GIT_URL:-}"
GIT_REF="${GIT_REF:-}"
LOCAL_PATH="${LOCAL_PATH:-}"
BUILD_JDK="${BUILD_JDK:-auto}"
SOURCE_LABEL="${SOURCE_LABEL:-}"

WORK="${WORKSPACE:-$(mktemp -d)}/argus-work"
SRC="$WORK/src"
CLASSPATH_FILE="$WORK/classpath.txt"

declare -A STATUS=()
STEPS=(gitleaks deps trivy-sbom trivy-vuln semgrep pmd eol)

log() { printf '\n==> [argus] %s\n' "$*"; }
die() { printf '[argus] ERROR: %s\n' "$*" >&2; exit 1; }

[[ "$APP_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || die "APP_NAME must match [A-Za-z0-9._-]+ (got '$APP_NAME')"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$REPORTS_ROOT/$APP_NAME/$STAMP"
STARTED_AT="$(date -Iseconds)"

rm -rf "$WORK"
mkdir -p "$SRC"

# ---------------------------------------------------------------- source
SOURCE_DESC=""
SOURCE_COMMIT=""

fetch_git() {
    [[ -n "$GIT_URL" ]] || die "GIT_URL is required when SOURCE_TYPE=git"
    local askpass=""
    if [[ -n "${GIT_TOKEN:-}" ]]; then
        # Token is handed to git through GIT_ASKPASS so it never appears in the URL or logs.
        askpass="$WORK/askpass.sh"
        cat > "$askpass" <<'EOF'
#!/bin/sh
case "$1" in
    Username*) printf '%s\n' "$GIT_USERNAME" ;;
    *) printf '%s\n' "$GIT_TOKEN" ;;
esac
EOF
        chmod 700 "$askpass"
    fi

    local ssh_askpass=""
    if [[ -n "${GIT_SSH_KEY_FILE:-}" ]]; then
        # Key file comes from the Jenkins sshUserPrivateKey binding. Unknown hosts are trusted on first
        # use and remembered in ~/.ssh/known_hosts (persisted in the jenkins_home volume).
        mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
        local ssh_cmd="ssh -i '$GIT_SSH_KEY_FILE' -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
        if [[ -n "${GIT_SSH_PASSPHRASE:-}" ]]; then
            # BatchMode would suppress the passphrase prompt, so the askpass helper answers it instead.
            ssh_askpass="$WORK/ssh-askpass.sh"
            printf '#!/bin/sh\nprintf "%%s\\n" "$GIT_SSH_PASSPHRASE"\n' > "$ssh_askpass"
            chmod 700 "$ssh_askpass"
            export SSH_ASKPASS="$ssh_askpass" SSH_ASKPASS_REQUIRE=force
        else
            ssh_cmd+=" -o BatchMode=yes"
        fi
        export GIT_SSH_COMMAND="$ssh_cmd"
    fi

    local args=(clone --depth 1 --quiet)
    [[ -n "$GIT_REF" ]] && args+=(--branch "$GIT_REF")
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$askpass" git -c credential.helper= "${args[@]}" "$GIT_URL" "$SRC"
    local helper
    for helper in "$askpass" "$ssh_askpass"; do
        if [[ -n "$helper" ]]; then rm -f -- "$helper"; fi
    done
    SOURCE_COMMIT="$(git -C "$SRC" rev-parse HEAD)"
    SOURCE_DESC="$GIT_URL${GIT_REF:+@$GIT_REF}"
}

fetch_local() {
    [[ -n "$LOCAL_PATH" ]] || die "LOCAL_PATH is required when SOURCE_TYPE=local"
    local root path
    root="$(realpath "$SOURCES_ROOT")"
    path="$(realpath -e "$SOURCES_ROOT/$LOCAL_PATH")" || die "local source not found: $LOCAL_PATH"
    [[ "$path" == "$root" || "$path" == "$root/"* ]] || die "LOCAL_PATH must stay inside $SOURCES_ROOT"
    # Copy so that generated lockfiles never touch the user's checkout.
    tar -C "$path" --exclude='./build' --exclude='./target' --exclude='./.gradle' \
        --exclude='./node_modules' -cf - . | tar -C "$SRC" -xf -
    if git -C "$SRC" rev-parse HEAD >/dev/null 2>&1; then
        SOURCE_COMMIT="$(git -C "$SRC" rev-parse HEAD)"
    fi
    SOURCE_DESC="local:$LOCAL_PATH"
}

log "Preparing source ($SOURCE_TYPE)"
case "$SOURCE_TYPE" in
    git) fetch_git ;;
    local) fetch_local ;;
    *) die "unknown SOURCE_TYPE: $SOURCE_TYPE" ;;
esac
# trigger-scan.sh passes the original host path when it scans a staging copy.
[[ -n "$SOURCE_LABEL" ]] && SOURCE_DESC="$SOURCE_LABEL"
echo "source: $SOURCE_DESC ${SOURCE_COMMIT:+($SOURCE_COMMIT)}"
# Created only after the source is ready, so a failed clone leaves no empty report folder.
mkdir -p "$OUT"
echo "output: $OUT"

# All scanners run from the source root so that SARIF locations are relative paths.
cd "$SRC"

# ---------------------------------------------------------------- steps
step_gitleaks() {
    gitleaks dir . --no-banner --redact --exit-code 0 \
        --report-format sarif --report-path "$OUT/gitleaks.sarif"
}

gradle_wrapper_version() {
    local props="gradle/wrapper/gradle-wrapper.properties"
    [[ -f "$props" ]] || return 0
    sed -n 's#.*gradle-\([0-9][0-9.]*\)-\(bin\|all\)\.zip.*#\1#p' "$props" | head -n 1
}

java_home_for() {
    case "$1" in
        8) echo /opt/java/jdk8 ;;
        17) echo /opt/java/jdk17 ;;
        21) echo /opt/java/openjdk ;;
        *) echo "unsupported BUILD_JDK: $1" >&2; return 1 ;;
    esac
}

# Trivy only understands gradle.lockfile, so resolve every configuration once with locking enabled.
resolve_gradle() {
    if [[ ! -f gradlew ]]; then
        echo "Gradle project without wrapper: dependency lockfiles cannot be generated"
        return 1
    fi

    local version major minor jdk java_home
    version="$(gradle_wrapper_version)"
    major="${version%%.*}"
    minor="$(cut -d. -f2 <<<"$version.0")"
    jdk="$BUILD_JDK"
    if [[ "$jdk" == auto ]]; then
        if [[ -z "$version" ]] || (( major > 7 || (major == 7 && minor >= 3) )); then jdk=17; else jdk=8; fi
    fi
    java_home="$(java_home_for "$jdk")"
    echo "gradle wrapper ${version:-unknown}, JDK $jdk"

    local args=(--no-daemon --console=plain --init-script "$ARGUS_HOME/argus-lock.init.gradle"
                "-Dargus.classpathFile=$CLASSPATH_FILE" argusResolveAndLockAll --write-locks)
    if [[ -n "$version" ]] && (( major > 6 || (major == 6 && minor >= 6) )); then
        args+=(--no-configuration-cache)
    fi
    chmod +x gradlew
    JAVA_HOME="$java_home" timeout 30m ./gradlew "${args[@]}"
    find . -name gradle.lockfile -not -path './.gradle/*' | sed 's#^#lockfile: #'
}

# Populates ~/.m2 so that Trivy reads POMs locally instead of hitting Maven Central per artifact
# (which gets rate limited with HTTP 429), and exports the compile classpath for PMD.
resolve_maven() {
    local jdk="$BUILD_JDK" java_home mvn=(mvn)
    [[ "$jdk" == auto ]] && jdk=17
    java_home="$(java_home_for "$jdk")"
    if [[ -f mvnw ]]; then
        chmod +x mvnw
        mvn=(./mvnw)
    fi
    echo "maven: ${mvn[*]}, JDK $jdk${MAVEN_MIRROR_URL:+, mirror $MAVEN_MIRROR_URL}"

    local args=(-B -q --fail-at-end)
    if [[ -n "${MAVEN_MIRROR_URL:-}" ]]; then
        cat > "$WORK/maven-settings.xml" <<EOF
<settings>
  <mirrors>
    <mirror>
      <id>argus-mirror</id>
      <mirrorOf>*</mirrorOf>
      <url>$MAVEN_MIRROR_URL</url>
    </mirror>
  </mirrors>
</settings>
EOF
        args+=(-s "$WORK/maven-settings.xml")
    fi
    local cp="$WORK/maven-classpath.txt"
    JAVA_HOME="$java_home" timeout 30m "${mvn[@]}" "${args[@]}" \
        org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath \
        "-Dmdep.outputFile=$cp" -Dmdep.appendOutput=true
    if [[ -f "$cp" ]]; then tr ':' '\n' < "$cp" >> "$CLASSPATH_FILE"; fi
}

step_deps() {
    : > "$CLASSPATH_FILE"
    if [[ -f build.gradle || -f build.gradle.kts ]]; then
        resolve_gradle
    elif [[ -f pom.xml ]]; then
        resolve_maven
    else
        echo "no Gradle or Maven build file"
        return 3
    fi
    echo "classpath entries: $(sort -u "$CLASSPATH_FILE" | grep -c . || true)"
}

step_trivy_sbom() {
    trivy "$TRIVY_MODE" . --quiet --format cyclonedx --output "$OUT/sbom.cdx.json"
}

step_trivy_vuln() {
    trivy "$TRIVY_MODE" . --quiet --scanners vuln --format sarif --output "$OUT/trivy.sarif"
}

step_semgrep() {
    local configs=()
    for c in $SEMGREP_CONFIGS; do configs+=(--config "$c"); done
    semgrep scan "${configs[@]}" --metrics=off --quiet --sarif --output "$OUT/semgrep.sarif" .
}

step_pmd() {
    local rc=0 args=()
    # Without the dependency classpath PMD 7 cannot resolve types and silently skips many rules.
    if [[ -s "$CLASSPATH_FILE" ]]; then
        sort -u "$CLASSPATH_FILE" -o "$CLASSPATH_FILE"
        args+=(--aux-classpath "file:$CLASSPATH_FILE")
    else
        echo "no dependency classpath: results may be incomplete"
    fi
    PMD_JAVA_DISABLE_AUX_CLASSPATH_WARNINGS=true pmd check --dir . --rulesets "$PMD_RULESET" --format sarif --report-file "$OUT/pmd.sarif" \
        --relativize-paths-with "$SRC" --no-fail-on-violation --no-progress --no-cache "${args[@]}" || rc=$?
    # 5 = some files could not be processed; the report is still usable.
    (( rc == 0 || rc == 5 )) || return "$rc"
}

step_eol() {
    python3 "$ARGUS_HOME/eol_enrich.py" --sbom "$OUT/sbom.cdx.json" --src .
}

# `trivy fs` reads only dependency manifests (pom.xml, gradle.lockfile) and ignores .jar files.
# Projects without Gradle/Maven (e.g. Ant with jars in lib/) are scanned with `trivy rootfs`,
# which identifies bundled jars instead.
if [[ -f build.gradle || -f build.gradle.kts || -f pom.xml ]]; then
    TRIVY_MODE=fs
else
    TRIVY_MODE=rootfs
fi
echo "trivy mode: $TRIVY_MODE"

# Each step runs in its own subshell with errexit, so one failing scanner does not stop the rest.
for step in "${STEPS[@]}"; do
    log "Step: $step"
    set +e
    ( set -e; "step_${step//-/_}" )
    rc=$?
    set -e
    case "$rc" in
        0) STATUS[$step]=success ;;
        3) STATUS[$step]=skipped ;;
        *) STATUS[$step]=failed; echo "[argus] step '$step' failed (exit code $rc)" >&2 ;;
    esac
done

# ---------------------------------------------------------------- manifest
tool_versions="$(
    printf 'gitleaks=%s\n' "$(gitleaks version 2>/dev/null)"
    printf 'trivy=%s\n' "$(trivy --version 2>/dev/null | sed -n 's/^Version: //p')"
    printf 'semgrep=%s\n' "$(semgrep --version 2>/dev/null)"
    printf 'pmd=%s\n' "$(pmd --version 2>/dev/null | sed -n 's/^PMD \([0-9.]*\).*/\1/p' | head -n 1)"
)"
step_status="$(for s in "${STEPS[@]}"; do printf '%s=%s\n' "$s" "${STATUS[$s]}"; done)"

APP_NAME="$APP_NAME" SOURCE_TYPE="$SOURCE_TYPE" SOURCE_DESC="$SOURCE_DESC" SOURCE_COMMIT="$SOURCE_COMMIT" \
STARTED_AT="$STARTED_AT" TOOL_VERSIONS="$tool_versions" STEP_STATUS="$step_status" OUT="$OUT" \
python3 - <<'PY'
import datetime, json, os
from pathlib import Path

def pairs(text):
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)

out = Path(os.environ["OUT"])
manifest = {
    "schemaVersion": 1,
    "application": os.environ["APP_NAME"],
    "source": {
        "type": os.environ["SOURCE_TYPE"],
        "location": os.environ["SOURCE_DESC"],
        "commit": os.environ["SOURCE_COMMIT"] or None,
    },
    "startedAt": os.environ["STARTED_AT"],
    "finishedAt": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    "jenkins": {"job": os.environ.get("JOB_NAME"), "build": os.environ.get("BUILD_NUMBER"),
                "url": os.environ.get("BUILD_URL")},
    "tools": pairs(os.environ["TOOL_VERSIONS"]),
    "steps": pairs(os.environ["STEP_STATUS"]),
    "files": sorted(p.name for p in out.iterdir() if p.name != "manifest.json"),
}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
PY

ln -sfn "$STAMP" "$REPORTS_ROOT/$APP_NAME/latest"

log "Summary"
for s in "${STEPS[@]}"; do printf '  %-12s %s\n' "$s" "${STATUS[$s]}"; done
ls -l "$OUT"

for s in "${STEPS[@]}"; do
    [[ "${STATUS[$s]}" != failed ]] || exit 2
done
