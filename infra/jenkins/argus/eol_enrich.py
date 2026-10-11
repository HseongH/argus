#!/usr/bin/env python3
"""Annotate a CycloneDX SBOM with end-of-life data from endoflife.date.

Library components are matched by Maven coordinates. The Java version and the
Gradle/Maven wrapper versions are read from build files and added as extra
components, because Trivy does not report them.

Every matched component gets `argus:eol:*` properties; the SBOM is rewritten in place.
"""
import argparse
import datetime
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

API = "https://endoflife.date/api/{}.json"
PREFIX = "argus:eol:"

# (groupId, artifactId) -> endoflife.date product.
# Only one representative artifact per product, so a product is not reported once per module.
MAVEN_PRODUCTS = {
    ("org.springframework.boot", "spring-boot"): "spring-boot",
    ("org.springframework", "spring-core"): "spring-framework",
    ("org.springframework.security", "spring-security-core"): "spring-security",
    ("org.hibernate.orm", "hibernate-core"): "hibernate-orm",
    ("org.hibernate", "hibernate-core"): "hibernate-orm",
    ("org.apache.tomcat.embed", "tomcat-embed-core"): "tomcat",
    ("org.apache.tomcat", "tomcat-catalina"): "tomcat",
    ("org.eclipse.jetty", "jetty-server"): "eclipse-jetty",
    ("org.apache.logging.log4j", "log4j-core"): "log4j",
    ("log4j", "log4j"): "log4j",
    ("org.apache.struts", "struts2-core"): "apache-struts",
    ("org.jetbrains.kotlin", "kotlin-stdlib"): "kotlin",
    ("io.quarkus", "quarkus-core"): "quarkus-framework",
}

# OpenJDK support windows differ by vendor; Temurin is used as the reference distribution.
JAVA_PRODUCT = "eclipse-temurin"

JAVA_PATTERNS = [
    re.compile(r"JavaLanguageVersion\.of\(\s*(\d+)\s*\)"),
    re.compile(r"(?:source|target)Compatibility\s*=\s*['\"]?(?:JavaVersion\.VERSION_)?(1[._]\d+|\d+)"),
    re.compile(r"jvmToolchain\(\s*(\d+)\s*\)"),
    re.compile(r"<java\.version>\s*([\d.]+)\s*</java\.version>"),
    re.compile(r"<maven\.compiler\.(?:source|target|release)>\s*([\d.]+)\s*<"),
    re.compile(r"<release>\s*(\d+)\s*</release>"),
    # Ant: <javac source="1.8"> and <property name="javac.source" value="1.8"/>
    re.compile(r"<javac\b[^>]*?\b(?:source|target|release)\s*=\s*\"(1\.\d+|\d+)\""),
    re.compile(r"name\s*=\s*\"(?:ant\.build\.)?javac\.(?:source|target|release)\"\s+value\s*=\s*\"(1\.\d+|\d+)\""),
]
BUILD_FILES = ("build.gradle", "build.gradle.kts", "pom.xml", "build.xml")
SKIP_DIRS = {".git", ".gradle", "build", "target", "node_modules"}


def fetch_cycles(product, cache):
    if product not in cache:
        url = API.format(urllib.parse.quote(product))
        req = urllib.request.Request(url, headers={"User-Agent": "argus-eol-enrich"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                cache[product] = json.load(resp)
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            print(f"[eol] lookup failed for {product}: {e}", file=sys.stderr)
            cache[product] = None
    return cache[product]


def match_cycle(cycles, version):
    """Return the most specific cycle whose name is a prefix of the version (e.g. 2.12 over 2)."""
    best = None
    for c in cycles:
        name = str(c["cycle"])
        if version == name or version.startswith(name + ".") or version.startswith(name + "+"):
            if best is None or len(name) > len(str(best["cycle"])):
                best = c
    return best


def is_eol(cycle, today):
    value = cycle.get("eol")
    if isinstance(value, bool):
        return value
    return datetime.date.fromisoformat(value) <= today


def evaluate(product, version, cycles, today):
    props = {"product": product, "version": version}
    if cycles is None:
        props["status"] = "lookup-failed"
        return props
    cycle = match_cycle(cycles, version)
    supported = [c for c in cycles if not is_eol(c, today)]  # newest first, as returned by the API
    if supported:
        props["latestCycle"] = str(supported[0]["cycle"])
    if cycle is None:
        props["status"] = "unknown-cycle"
        return props

    eol = is_eol(cycle, today)
    props.update({
        "status": "eol" if eol else "supported",
        "cycle": str(cycle["cycle"]),
        "eolDate": str(cycle["eol"]).lower() if isinstance(cycle["eol"], bool) else cycle["eol"],
        "latestInCycle": str(cycle.get("latest", "")),
    })
    if cycle.get("extendedSupport") not in (None, False):
        props["extendedSupport"] = str(cycle["extendedSupport"]).lower()

    if eol:
        # Smallest jump to a supported cycle, and the newest LTS when the product has one.
        newer = [c for c in supported if _key(c["cycle"]) > _key(cycle["cycle"])]
        target = newer[-1] if newer else (supported[-1] if supported else None)
        lts = [c for c in supported if c.get("lts")]
        if target:
            props["minimumSupportedCycle"] = str(target["cycle"])
            props["recommendation"] = (f"Upgrade to {product} {target['cycle']}.x "
                                       f"(latest {target.get('latest', '?')})")
        if lts:
            props["latestLtsCycle"] = str(lts[0]["cycle"])
            props["recommendation"] = (props.get("recommendation", "Upgrade")
                                       + f"; latest LTS is {lts[0]['cycle']}")
        if not target and not lts:
            props["recommendation"] = "No supported release line found"
    elif props["latestInCycle"] and props["latestInCycle"] != version:
        props["recommendation"] = f"Update to latest patch {props['latestInCycle']}"
    return props


def _key(cycle):
    return tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.+]", str(cycle)))


def parse_purl(purl):
    m = re.match(r"pkg:maven/([^/]+)/([^@]+)@([^?#]+)", purl or "")
    if not m:
        return None
    return urllib.parse.unquote(m.group(1)), urllib.parse.unquote(m.group(2)), urllib.parse.unquote(m.group(3))


def iter_build_files(src):
    for path in src.rglob("*"):
        if path.name in BUILD_FILES and not SKIP_DIRS.intersection(path.relative_to(src).parts[:-1]):
            yield path


def detect_java_versions(src):
    found = set()
    for path in iter_build_files(src):
        text = path.read_text(errors="ignore")
        for pattern in JAVA_PATTERNS:
            for raw in pattern.findall(text):
                v = raw.replace("_", ".")
                found.add(v[2:] if v.startswith("1.") else v)
    return sorted(found, key=lambda v: int(v) if v.isdigit() else 0)


def detect_wrapper(src, props_path, pattern):
    path = src / props_path
    if path.is_file():
        m = re.search(pattern, path.read_text(errors="ignore"))
        if m:
            return m.group(1)
    return None


def set_props(component, props):
    kept = [p for p in component.get("properties", []) if not p["name"].startswith(PREFIX)]
    kept += [{"name": PREFIX + k, "value": str(v)} for k, v in props.items()]
    component["properties"] = kept


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--src", required=True, type=Path)
    args = parser.parse_args()

    if args.sbom.is_file():
        bom = json.loads(args.sbom.read_text())
    else:
        print(f"[eol] {args.sbom} not found, creating an empty CycloneDX SBOM", file=sys.stderr)
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6",
               "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1, "components": []}
    components = bom.setdefault("components", [])
    src = args.src.resolve()
    today = datetime.date.today()
    cache = {}
    results = []

    for comp in components:
        coords = parse_purl(comp.get("purl"))
        if not coords:
            continue
        product = MAVEN_PRODUCTS.get(coords[:2])
        if product:
            props = evaluate(product, coords[2], fetch_cycles(product, cache), today)
            set_props(comp, props)
            results.append((f"{coords[0]}:{coords[1]}", props))

    # Runtime/tooling components detected from build files.
    runtime = []
    for v in detect_java_versions(src):
        runtime.append(("java", v, "platform", JAVA_PRODUCT))
    gradle = detect_wrapper(src, "gradle/wrapper/gradle-wrapper.properties", r"gradle-([\d.]+)-(?:bin|all)\.zip")
    if gradle:
        runtime.append(("gradle", gradle, "application", "gradle"))
    maven = detect_wrapper(src, ".mvn/wrapper/maven-wrapper.properties", r"apache-maven-([\d.]+)-bin")
    if maven:
        runtime.append(("maven", maven, "application", "apache-maven"))

    components[:] = [c for c in components if not str(c.get("bom-ref", "")).startswith("argus:runtime:")]
    for name, version, ctype, product in runtime:
        comp = {"bom-ref": f"argus:runtime:{name}:{version}", "type": ctype, "name": name, "version": version}
        props = evaluate(product, version, fetch_cycles(product, cache), today)
        set_props(comp, props)
        components.append(comp)
        results.append((name, props))

    meta = bom.setdefault("metadata", {})
    set_props(meta, {"checkedAt": today.isoformat(), "source": "https://endoflife.date"})
    args.sbom.write_text(json.dumps(bom, indent=2, ensure_ascii=False) + "\n")

    print(f"[eol] {len(results)} component(s) evaluated")
    for name, props in results:
        line = f"  {name:<50} {props['version']:<16} {props['status']}"
        if "recommendation" in props:
            line += f"  -> {props['recommendation']}"
        print(line)
    return 1 if any(p["status"] == "lookup-failed" for _, p in results) else 0


if __name__ == "__main__":
    sys.exit(main())
