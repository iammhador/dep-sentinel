#!/usr/bin/env python3
"""dep-sentinel scanner.

Finds known vulnerabilities in a project's dependencies with every scanner that
is installed, checks that lockfiles match their manifests, and looks for leaked
secrets. Prints one normalized report and exits with:

    0  clean
    1  findings below the gate, or an ecosystem nobody could scan (warning)
    2  blocking: a finding at/above the gate, a leaked secret, or a lockfile
       that no longer matches its manifest

Standard library only (Python 3.8+), so it runs anywhere Python does.
Missing scanners are reported as "skipped" and are never counted as a pass.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

VERSION = "1.0.0"
SEVERITIES = ["low", "moderate", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SKIP_DIRS = {
    "node_modules", ".git", "vendor", ".venv", "venv", "env", "__pycache__",
    "target", "dist", "build", ".next", ".nuxt", ".svelte-kit", "bower_components",
    ".tox", ".mypy_cache", ".gradle", "Pods", ".terraform",
    # Test fixtures are often intentionally vulnerable; they are not shipped dependencies.
    "evals", "fixtures", "__fixtures__", "testdata", "test-fixtures",
}
TOOL_TIMEOUT = int(os.environ.get("DEP_SENTINEL_TIMEOUT", "180"))


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def which(name: str) -> str | None:
    return shutil.which(name)


def run(cmd: list[str], cwd: Path, timeout: int = TOOL_TIMEOUT, env: dict | None = None):
    """Run a command; return (returncode, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout,
            env={**os.environ, **(env or {})}, stdin=subprocess.DEVNULL,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except (OSError, ValueError) as exc:
        return 127, "", str(exc)


def json_loads_lenient(text: str):
    """Parse JSON that may be preceded by log lines."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    for opener in ("{", "["):
        idx = text.find(opener)
        if idx != -1:
            try:
                return json.loads(text[idx:])
            except ValueError:
                continue
    return None


def json_stream(text: str):
    """Yield every JSON value from a stream of concatenated/NDJSON objects."""
    decoder = json.JSONDecoder()
    idx, n = 0, len(text)
    while idx < n:
        while idx < n and text[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
        except ValueError:
            nl = text.find("\n", idx)
            if nl == -1:
                break
            idx = nl + 1
            continue
        yield obj
        idx = end


def norm_sev(value) -> str:
    """Map any tool's severity label/score to low|moderate|high|critical|unknown."""
    if value is None or value == "":
        return "unknown"
    if isinstance(value, (int, float)):
        return score_to_sev(float(value))
    v = str(value).strip().lower()
    try:
        return score_to_sev(float(v))
    except ValueError:
        pass
    if v.startswith("cvss:3"):
        score = cvss3_score(v)
        return score_to_sev(score) if score is not None else "unknown"
    return {
        "critical": "critical", "high": "high", "important": "high",
        "moderate": "moderate", "medium": "moderate",
        "low": "low", "info": "low", "informational": "low", "negligible": "low",
    }.get(v, "unknown")


def score_to_sev(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "moderate"
    if score > 0:
        return "low"
    return "unknown"


_CVSS_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss3_score(vector: str):
    """Base score of a CVSS v3.x vector (spec section 7.1)."""
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - _CVSS_W["C"][parts["C"]]) * (1 - _CVSS_W["I"][parts["I"]]) * (1 - _CVSS_W["A"][parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploit = 8.22 * _CVSS_W["AV"][parts["AV"]] * _CVSS_W["AC"][parts["AC"]] * pr * _CVSS_W["UI"][parts["UI"]]
        if impact <= 0:
            return 0.0
        raw = min(1.08 * (impact + exploit), 10) if scope_changed else min(impact + exploit, 10)
        return math.ceil(raw * 10 - 1e-9) / 10
    except (KeyError, ValueError, IndexError):
        return None


def finding(tool, ecosystem, manifest, package, version, severity, vid, title="", url="",
            fixed="", aliases=None, note="", affected=""):
    return {
        "tool": tool, "ecosystem": ecosystem, "manifest": manifest, "package": package,
        "version": version or "", "affected": affected or "", "severity": severity, "id": vid or "", "aliases": sorted(set(aliases or [])),
        "title": clean_title(title)[:200], "url": url or "",
        "fixed": fixed or "", "note": note,
    }


# --------------------------------------------------------------------------
# project discovery
# --------------------------------------------------------------------------

def discover(root: Path, max_depth: int = 4):
    """Return {filename: [paths]} for interesting manifests/lockfiles."""
    wanted = {
        "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
        "bun.lock", "bun.lockb", "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock",
        "pyproject.toml", "Cargo.lock", "go.mod", "composer.lock", "Gemfile.lock",
        "packages.lock.json", "pom.xml", "build.gradle", "build.gradle.kts",
    }
    found: dict[str, list[Path]] = {}
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).parts) - root_depth
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".") or d == ".github"]
        if depth >= max_depth:
            dirnames[:] = []
        for name in filenames:
            if name in wanted or re.match(r"requirements[-_.\w]*\.txt$", name) or name.endswith((".csproj", ".fsproj")):
                key = "requirements.txt" if name.startswith("requirements") else name
                key = "dotnet-project" if name.endswith((".csproj", ".fsproj")) else key
                found.setdefault(key, []).append(Path(dirpath) / name)
    return found


def node_projects(found):
    """Each folder with a Node lockfile, and which package manager owns it."""
    order = [("bun.lock", "bun"), ("bun.lockb", "bun"), ("pnpm-lock.yaml", "pnpm"),
             ("yarn.lock", "yarn"), ("package-lock.json", "npm"), ("npm-shrinkwrap.json", "npm")]
    projects: dict[Path, tuple[str, Path]] = {}
    for lock, pm in order:
        for path in found.get(lock, []):
            projects.setdefault(path.parent, (pm, path))
    return projects


def installed_versions(lock: Path) -> dict:
    """{package: [versions]} read from a Node lockfile, so reports show what is actually installed."""
    versions: dict[str, set] = {}
    try:
        text = lock.read_text(errors="replace")
    except OSError:
        return {}
    if lock.name == "bun.lock":
        for name, ver in re.findall(r'^\s*"[^"]+":\s*\["((?:@[^/@"]+/)?[^@"]+)@([^"]+)"', text, re.M):
            versions.setdefault(name, set()).add(ver)
    elif lock.name in ("package-lock.json", "npm-shrinkwrap.json"):
        try:
            for path, meta in (json.loads(text).get("packages") or {}).items():
                if path and "node_modules/" in path and isinstance(meta, dict) and meta.get("version"):
                    versions.setdefault(path.rsplit("node_modules/", 1)[1], set()).add(meta["version"])
        except ValueError:
            pass
    elif lock.name == "pnpm-lock.yaml":
        for name, ver in re.findall(r"^\s{2}'?/?((?:@[^/@\s']+/)?[^@/\s']+)@([0-9][^:'(\s]*)", text, re.M):
            versions.setdefault(name, set()).add(ver)
    elif lock.name == "yarn.lock":
        for block in text.split("\n\n"):
            head = re.match(r'^"?((?:@[^/@"]+/)?[^@"\s,]+)@', block.strip())
            ver = re.search(r'^\s+version:?\s+"?([^"\s]+)', block, re.M)
            if head and ver:
                versions.setdefault(head.group(1), set()).add(ver.group(1))
    return {k: sorted(v) for k, v in versions.items()}


# --------------------------------------------------------------------------
# scanners: each returns (findings, status) where status is
# {"tool", "target", "state": ran|skipped|error, "detail"}
# --------------------------------------------------------------------------

def status(tool, target, state, detail=""):
    return {"tool": tool, "target": target, "state": state, "detail": detail}


def scan_npm(folder: Path, rel: str):
    if not which("npm"):
        return [], status("npm audit", rel, "skipped", "npm not installed")
    code, out, err = run(["npm", "audit", "--json"], folder)
    data = json_loads_lenient(out)
    if not isinstance(data, dict) or ("vulnerabilities" not in data and "advisories" not in data):
        return [], status("npm audit", rel, "error", (err or out)[-300:])
    results = []
    installed = installed_versions(folder / "package-lock.json")
    for name, vuln in (data.get("vulnerabilities") or {}).items():
        for via in vuln.get("via", []):
            if not isinstance(via, dict):
                continue  # an indirect pointer; the root advisory is reported on its own package
            vid = (via.get("url") or "").rstrip("/").split("/")[-1]
            fix = vuln.get("fixAvailable")
            fixed = "" if not fix else (f"{fix.get('name')}@{fix.get('version')}" if isinstance(fix, dict) else "available")
            pkg_name = via.get("name") or name
            results.append(finding("npm audit", "npm", rel, pkg_name, ", ".join(installed.get(pkg_name, [])),
                                   norm_sev(via.get("severity")), vid, via.get("title"), via.get("url"), fixed,
                                   [vid] if vid.startswith("GHSA") else [], affected=via.get("range", "")))
    return results, status("npm audit", rel, "ran")


def scan_bun(folder: Path, rel: str):
    if not which("bun"):
        return [], status("bun audit", rel, "skipped", "bun not installed")
    code, out, err = run(["bun", "audit", "--json"], folder)
    data = json_loads_lenient(out)
    if not isinstance(data, dict):
        if code == 0 and not out.strip():
            return [], status("bun audit", rel, "ran")
        return [], status("bun audit", rel, "error", (err or out)[-300:])
    results = []
    installed = installed_versions(folder / "bun.lock")
    for name, advisories in data.items():
        for adv in advisories if isinstance(advisories, list) else []:
            url = adv.get("url", "")
            vid = url.rstrip("/").split("/")[-1] if url else str(adv.get("id", ""))
            results.append(finding("bun audit", "npm", rel, name, ", ".join(installed.get(name, [])),
                                   norm_sev(adv.get("severity")), vid, adv.get("title"), url, "",
                                   [vid] if vid.startswith("GHSA") else [], affected=adv.get("vulnerable_versions", "")))
    return results, status("bun audit", rel, "ran")


def scan_pnpm(folder: Path, rel: str):
    if not which("pnpm"):
        return [], status("pnpm audit", rel, "skipped", "pnpm not installed")
    code, out, err = run(["pnpm", "audit", "--json"], folder)
    data = json_loads_lenient(out)
    if not isinstance(data, dict):
        return [], status("pnpm audit", rel, "error", (err or out)[-300:])
    results = []
    for adv in (data.get("advisories") or {}).values():
        versions = sorted({f.get("version", "") for f in adv.get("findings", [])})
        url = adv.get("url", "")
        vid = url.rstrip("/").split("/")[-1] if url else str(adv.get("id", ""))
        results.append(finding("pnpm audit", "npm", rel, adv.get("module_name"), ", ".join(versions),
                               norm_sev(adv.get("severity")), vid, adv.get("title"), url,
                               adv.get("patched_versions", ""), (adv.get("cves") or []) + ([vid] if vid.startswith("GHSA") else [])))
    return results, status("pnpm audit", rel, "ran")


def scan_yarn(folder: Path, rel: str):
    if not which("yarn"):
        return [], status("yarn audit", rel, "skipped", "yarn not installed")
    _, ver, _ = run(["yarn", "--version"], folder, 30)
    berry = ver.strip()[:1] not in ("", "0", "1")
    cmd = ["yarn", "npm", "audit", "--json", "--recursive"] if berry else ["yarn", "audit", "--json"]
    code, out, err = run(cmd, folder)
    results = []
    for obj in json_stream(out):
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "auditAdvisory":  # yarn 1
            adv = obj.get("data", {}).get("advisory", {})
            url = adv.get("url", "")
            vid = url.rstrip("/").split("/")[-1] if url else str(adv.get("id", ""))
            versions = sorted({f.get("version", "") for f in adv.get("findings", [])})
            results.append(finding("yarn audit", "npm", rel, adv.get("module_name"), ", ".join(versions),
                                   norm_sev(adv.get("severity")), vid, adv.get("title"), url,
                                   adv.get("patched_versions", ""), adv.get("cves") or []))
        elif "children" in obj:  # yarn berry
            ch = obj["children"]
            url = ch.get("URL", "")
            vid = url.rstrip("/").split("/")[-1] if url else str(ch.get("ID", ""))
            tree = ch.get("Tree Versions") or []
            results.append(finding("yarn npm audit", "npm", rel, obj.get("value"), ", ".join(tree),
                                   norm_sev(ch.get("Severity")), vid, ch.get("Issue"), url,
                                   "", [vid] if vid.startswith("GHSA") else [], affected=ch.get("Vulnerable Versions", "")))
    if code not in (0, 1) and not results and "Usage Error" in (err + out):
        return [], status("yarn audit", rel, "error", (err or out)[-300:])
    return results, status("yarn audit", rel, "ran")


def pip_audit_cmd():
    if which("pip-audit"):
        return ["pip-audit"]
    if which("uvx"):
        return ["uvx", "pip-audit"]
    if which("pipx"):
        return ["pipx", "run", "pip-audit"]
    return None


def scan_pip(req: Path, rel: str):
    base = pip_audit_cmd()
    if not base:
        return [], status("pip-audit", rel, "skipped", "install pip-audit (or uv/pipx)")
    code, out, err = run(base + ["-r", str(req), "-f", "json", "--progress-spinner", "off"], req.parent, max(TOOL_TIMEOUT, 300))
    data = json_loads_lenient(out)
    if not isinstance(data, dict):
        return [], status("pip-audit", rel, "error", (err or out)[-300:])
    results = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            results.append(finding("pip-audit", "PyPI", rel, dep.get("name"), dep.get("version"),
                                   "unknown", v.get("id"), v.get("description", ""),
                                   f"https://osv.dev/vulnerability/{v.get('id')}",
                                   ", ".join(v.get("fix_versions") or []), v.get("aliases") or [],
                                   "pip-audit reports no severity; treated as high until triaged"))
    return results, status("pip-audit", rel, "ran")


def scan_cargo(lock: Path, rel: str):
    if not which("cargo") or run(["cargo", "audit", "--version"], lock.parent, 30)[0] != 0:
        return [], status("cargo audit", rel, "skipped", "install with: cargo install cargo-audit")
    code, out, err = run(["cargo", "audit", "--json"], lock.parent)
    data = json_loads_lenient(out)
    if not isinstance(data, dict):
        return [], status("cargo audit", rel, "error", (err or out)[-300:])
    results = []
    for item in (data.get("vulnerabilities") or {}).get("list", []):
        adv, pkg = item.get("advisory", {}), item.get("package", {})
        results.append(finding("cargo audit", "crates.io", rel, pkg.get("name"), pkg.get("version"),
                               norm_sev(adv.get("cvss")), adv.get("id"), adv.get("title"), adv.get("url"),
                               ", ".join((item.get("versions") or {}).get("patched") or []), adv.get("aliases") or []))
    return results, status("cargo audit", rel, "ran")


def scan_go(gomod: Path, rel: str):
    if which("govulncheck"):
        cmd = ["govulncheck", "-json", "./..."]
    elif which("go"):
        cmd = ["go", "run", "golang.org/x/vuln/cmd/govulncheck@latest", "-json", "./..."]
    else:
        return [], status("govulncheck", rel, "skipped", "Go toolchain not installed")
    code, out, err = run(cmd, gomod.parent, max(TOOL_TIMEOUT, 300))
    osvs, results, seen = {}, [], set()
    for obj in json_stream(out):
        if not isinstance(obj, dict):
            continue
        if "osv" in obj:
            osvs[obj["osv"].get("id")] = obj["osv"]
        elif "finding" in obj:
            f = obj["finding"]
            trace = f.get("trace") or [{}]
            called = any(t.get("function") for t in trace)
            key = (f.get("osv"), trace[0].get("module"), called)
            if key in seen:
                continue
            seen.add(key)
            osv = osvs.get(f.get("osv"), {})
            results.append(finding("govulncheck", "Go", rel, trace[0].get("module"), trace[0].get("version"),
                                   "unknown" if called else "low", f.get("osv"), osv.get("summary"),
                                   f"https://pkg.go.dev/vuln/{f.get('osv')}", f.get("fixed_version", ""),
                                   osv.get("aliases") or [],
                                   "reachable from your code" if called else "imported but not called"))
    if code not in (0, 3) and not results:
        return [], status("govulncheck", rel, "error", (err or out)[-300:])
    return results, status("govulncheck", rel, "ran")


def scan_composer(lock: Path, rel: str):
    if not which("composer"):
        return [], status("composer audit", rel, "skipped", "composer not installed")
    code, out, err = run(["composer", "audit", "--format=json", "--locked", "--no-interaction"], lock.parent)
    data = json_loads_lenient(out)
    if not isinstance(data, dict):
        return [], status("composer audit", rel, "error", (err or out)[-300:])
    results = []
    advisories = data.get("advisories") or {}
    for pkg, advs in (advisories.items() if isinstance(advisories, dict) else []):
        for adv in advs if isinstance(advs, list) else advs.values():
            results.append(finding("composer audit", "Packagist", rel, pkg, adv.get("affectedVersions", ""),
                                   norm_sev(adv.get("severity")), adv.get("advisoryId") or adv.get("cve"),
                                   adv.get("title"), adv.get("link"), "", [adv["cve"]] if adv.get("cve") else []))
    return results, status("composer audit", rel, "ran")


def scan_bundler(lock: Path, rel: str):
    if not which("bundle-audit"):
        return [], status("bundle-audit", rel, "skipped", "install with: gem install bundler-audit")
    run(["bundle-audit", "update"], lock.parent, 120)
    code, out, err = run(["bundle-audit", "check", "--format", "json"], lock.parent)
    data = json_loads_lenient(out)
    if not isinstance(data, dict):
        return [], status("bundle-audit", rel, "error", (err or out)[-300:])
    results = []
    for r in data.get("results", []):
        gem, adv = r.get("gem", {}), r.get("advisory", {})
        aliases = [a for a in (adv.get("cve") and f"CVE-{adv['cve']}", adv.get("ghsa") and f"GHSA-{adv['ghsa']}") if a]
        results.append(finding("bundle-audit", "RubyGems", rel, gem.get("name"), gem.get("version"),
                               norm_sev(adv.get("criticality")), adv.get("id"), adv.get("title"), adv.get("url"),
                               ", ".join(adv.get("patched_versions") or []), aliases))
    return results, status("bundle-audit", rel, "ran")


def scan_dotnet(project: Path, rel: str):
    if not which("dotnet"):
        return [], status("dotnet vulnerable", rel, "skipped", "dotnet SDK not installed")
    code, out, err = run(["dotnet", "list", str(project), "package", "--vulnerable", "--include-transitive",
                          "--format", "json"], project.parent, max(TOOL_TIMEOUT, 300))
    data = json_loads_lenient(out)
    if not isinstance(data, dict):
        return [], status("dotnet vulnerable", rel, "error", (err or out)[-300:])
    results = []
    for proj in data.get("projects", []):
        for fw in proj.get("frameworks", []):
            for pkg in fw.get("topLevelPackages", []) + fw.get("transitivePackages", []):
                for v in pkg.get("vulnerabilities", []):
                    url = v.get("advisoryurl", "")
                    vid = url.rstrip("/").split("/")[-1]
                    results.append(finding("dotnet vulnerable", "NuGet", rel, pkg.get("id"), pkg.get("resolvedVersion"),
                                           norm_sev(v.get("severity")), vid, "", url, "",
                                           [vid] if vid.startswith("GHSA") else []))
    return results, status("dotnet vulnerable", rel, "ran")


def scan_osv(root: Path):
    """OSV-Scanner: one universal cross-check over every supported lockfile."""
    if not which("osv-scanner"):
        return [], status("osv-scanner", ".", "skipped", "optional: install OSV-Scanner for a cross-check")
    code, out, err = run(["osv-scanner", "scan", "source", "-r", "--format", "json", "."], root, max(TOOL_TIMEOUT, 300))
    data = json_loads_lenient(out)
    if not isinstance(data, dict):  # v1 CLI
        code, out, err = run(["osv-scanner", "--format", "json", "-r", "."], root, max(TOOL_TIMEOUT, 300))
        data = json_loads_lenient(out)
    if not isinstance(data, dict):
        return [], status("osv-scanner", ".", "error", (err or out)[-300:])
    results = []
    for res in data.get("results") or []:
        src = os.path.relpath(res.get("source", {}).get("path", "."), root)
        for pkg in res.get("packages") or []:
            meta = pkg.get("package", {})
            group_sev = {}
            for g in pkg.get("groups") or []:
                for i in g.get("ids", []):
                    group_sev[i] = g.get("max_severity")
            for v in pkg.get("vulnerabilities") or []:
                sev = norm_sev(group_sev.get(v.get("id")))
                if sev == "unknown":
                    sev = norm_sev((v.get("database_specific") or {}).get("severity"))
                if sev == "unknown":
                    for s in v.get("severity") or []:
                        sev = norm_sev(s.get("score"))
                        if sev != "unknown":
                            break
                results.append(finding("osv-scanner", meta.get("ecosystem"), src, meta.get("name"), meta.get("version"),
                                       sev, v.get("id"), v.get("summary"), f"https://osv.dev/vulnerability/{v.get('id')}",
                                       "", v.get("aliases") or []))
    return results, status("osv-scanner", ".", "ran")


# --------------------------------------------------------------------------
# lockfile sync
# --------------------------------------------------------------------------

def npm_lock_in_sync(folder: Path):
    """Same check `npm ci` does: every manifest range must be the one recorded in the lockfile."""
    try:
        pkg = json.loads((folder / "package.json").read_text())
        lock = json.loads((folder / "package-lock.json").read_text())
    except (OSError, ValueError) as exc:
        return None, f"could not read: {exc}"
    root = (lock.get("packages") or {}).get("")
    if root is None:
        return None, "lockfileVersion 1 is not checked"
    problems = []
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        want, have = pkg.get(field) or {}, root.get(field) or {}
        for name, spec in want.items():
            if have.get(name) != spec:
                problems.append(f"{name}: package.json {spec!r} vs lockfile {have.get(name)!r}")
        for name in have:
            if name not in want:
                problems.append(f"{name}: in lockfile but not in package.json")
    return not problems, "; ".join(problems[:5])


def check_lockfiles(found, root: Path):
    results = []

    def rel(p: Path) -> str:
        return os.path.relpath(p, root)

    for folder, (pm, lock) in node_projects(found).items():
        if pm == "npm":
            ok, detail = npm_lock_in_sync(folder)
        elif pm == "bun" and which("bun"):
            code, out, err = run(["bun", "install", "--frozen-lockfile", "--dry-run", "--ignore-scripts"], folder, 120)
            ok, detail = code == 0, "" if code == 0 else (err or out).strip().splitlines()[-1][:200]
        elif pm == "pnpm" and which("pnpm"):
            code, out, err = run(["pnpm", "install", "--frozen-lockfile", "--lockfile-only", "--ignore-scripts"], folder, 180)
            ok, detail = code == 0, "" if code == 0 else (err or out).strip()[-200:]
        else:
            ok, detail = None, f"{pm} lockfile not checked"
        results.append({"lockfile": rel(lock), "in_sync": ok, "detail": detail})
    for lock in found.get("Cargo.lock", []):
        if which("cargo"):
            code, out, err = run(["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"], lock.parent, 180)
            results.append({"lockfile": rel(lock), "in_sync": code == 0, "detail": "" if code == 0 else err.strip()[-200:]})
    for gomod in found.get("go.mod", []):
        if which("go"):
            code, out, err = run(["go", "mod", "tidy", "-diff"], gomod.parent, 180)
            if "flag provided but not defined" in err:
                continue  # Go < 1.23 cannot check without modifying files
            results.append({"lockfile": rel(gomod), "in_sync": code == 0, "detail": "" if code == 0 else "go.mod/go.sum need `go mod tidy`"})
    for lock in found.get("poetry.lock", []):
        if which("poetry"):
            code, out, err = run(["poetry", "check", "--lock"], lock.parent, 120)
            results.append({"lockfile": rel(lock), "in_sync": code == 0, "detail": "" if code == 0 else (err or out).strip()[-200:]})
    for lock in found.get("uv.lock", []):
        if which("uv"):
            code, out, err = run(["uv", "lock", "--check"], lock.parent, 180)
            results.append({"lockfile": rel(lock), "in_sync": code == 0, "detail": "" if code == 0 else (err or out).strip()[-200:]})
    for lock in found.get("composer.lock", []):
        if which("composer"):
            code, out, err = run(["composer", "validate", "--no-check-publish", "--no-interaction"], lock.parent, 120)
            stale = "lock file is not up to date" in (out + err).lower()
            results.append({"lockfile": rel(lock), "in_sync": not stale, "detail": "composer.lock is not up to date" if stale else ""})
    return results


# --------------------------------------------------------------------------
# secrets
# --------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("OpenAI/Anthropic key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("credentials in URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]{2,}:[^\s:/@'\"]{6,}@[A-Za-z0-9.-]+")),
]
ENV_FILE = re.compile(r"(^|/)\.env(\.[A-Za-z0-9_-]+)?$")
ENV_OK = re.compile(r"\.(example|sample|template|dist|defaults?)$")
PLACEHOLDER = re.compile(r"(example|placeholder|changeme|your[_-]|xxxx|dummy|<[^>]+>|\$\{)", re.I)


def mask(s: str) -> str:
    return s[:6] + "…" + s[-2:] if len(s) > 12 else "…"


def secrets_from_text(path: str, text: str, out: list):
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            continue
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(line):
                if PLACEHOLDER.search(m.group(0)) or (label == "credentials in URL" and PLACEHOLDER.search(line)):
                    continue
                out.append({"file": path, "line": lineno, "type": label, "match": mask(m.group(0))})


def scan_secrets(root: Path, ranges: list[str]):
    """gitleaks when installed; otherwise a built-in pattern scan."""
    results, tool = [], "built-in patterns"
    is_git = run(["git", "rev-parse", "--is-inside-work-tree"], root, 15)[0] == 0
    if not is_git:
        return results, "skipped (not a git repository)"

    if which("gitleaks"):
        tool = "gitleaks"
        report = root / ".git" / "dep-sentinel-gitleaks.json" if (root / ".git").is_dir() else Path(os.devnull)
        log_opts = " ".join(ranges) if ranges else None
        cmd = ["gitleaks", "git", "--no-banner", "--report-format", "json", "--report-path", str(report), "--exit-code", "0"]
        if log_opts:
            cmd += ["--log-opts", log_opts]
        code, out, err = run(cmd, root, 300)
        if "unknown command" in err:  # gitleaks < 8.19
            cmd = ["gitleaks", "detect", "--no-banner", "--report-format", "json", "--report-path", str(report), "--exit-code", "0"]
            if log_opts:
                cmd += ["--log-opts", log_opts]
            code, out, err = run(cmd, root, 300)
        try:
            for leak in json.loads(report.read_text()) if report.exists() else []:
                results.append({"file": leak.get("File"), "line": leak.get("StartLine"), "type": leak.get("Description") or leak.get("RuleID"),
                                "match": mask(leak.get("Secret", ""))})
        except (OSError, ValueError):
            pass
        finally:
            if report.exists() and report != Path(os.devnull):
                report.unlink()
    else:
        if ranges:
            for rng in ranges:
                import shlex
                code, out, _ = run(["git", "log", "-p", "--no-color", "--unified=0", "--format="] + shlex.split(rng), root, 120)
                current = "?"
                added = []
                for line in out.splitlines():
                    if line.startswith("+++ b/"):
                        current = line[6:]
                    elif line.startswith("+") and not line.startswith("+++"):
                        added.append((current, line[1:]))
                by_file: dict[str, list[str]] = {}
                for fname, added_line in added:
                    by_file.setdefault(fname, []).append(added_line)
                for f, lines in by_file.items():
                    secrets_from_text(f, "\n".join(lines), results)
        else:
            _, files, _ = run(["git", "ls-files", "-z"], root, 60)
            for f in [x for x in files.split("\0") if x]:
                p = root / f
                try:
                    if p.stat().st_size > 1_000_000:
                        continue
                    data = p.read_bytes()
                except OSError:
                    continue
                if b"\0" in data[:2048]:
                    continue
                secrets_from_text(f, data.decode("utf-8", "replace"), results)

    # A tracked .env file is a leak even when no pattern matches.
    _, files, _ = run(["git", "ls-files"], root, 60)
    for f in files.splitlines():
        if ENV_FILE.search(f) and not ENV_OK.search(f):
            results.append({"file": f, "line": 0, "type": ".env file committed to git", "match": ""})
    return results, tool


# --------------------------------------------------------------------------
# ignores (with expiry)
# --------------------------------------------------------------------------

def load_ignores(root: Path):
    """Return ({id: {reason, expires, source}}, [warnings]). Expired entries are dropped with a warning."""
    today = _dt.date.today()
    ignores, warnings = {}, []

    def add(vid, expires, reason, source):
        vid = (vid or "").strip()
        if not vid:
            return
        if expires:
            try:
                exp = _dt.date.fromisoformat(str(expires)[:10])
                if exp < today:
                    warnings.append(f"{vid}: ignore in {source} expired on {exp}; it counts again")
                    return
            except ValueError:
                pass
        ignores[vid.upper()] = {"reason": (reason or "").strip(), "expires": str(expires or "")[:10], "source": source}

    # .dep-sentinel-ignore: "<ID> [expires=YYYY-MM-DD] [reason=...]"
    f = root / ".dep-sentinel-ignore"
    if f.exists():
        for line in f.read_text().splitlines():
            line = line.split("#", 1)[0].strip() if not line.strip().startswith("#") else ""
            if not line:
                continue
            vid = line.split()[0]
            exp = re.search(r"expires=(\S+)", line)
            reason = re.search(r"reason=(.+)$", line)
            add(vid, exp and exp.group(1), reason and reason.group(1), ".dep-sentinel-ignore")

    # .snyk (YAML) — only the parts we need, without a YAML dependency.
    f = root / ".snyk"
    if f.exists():
        current, exp, reason = None, None, ""
        for line in f.read_text().splitlines():
            m = re.match(r"^\s{2}([A-Za-z0-9:_.-]+):\s*$", line)
            if m:
                if current:
                    add(current, exp, reason, ".snyk")
                current, exp, reason = m.group(1), None, ""
                continue
            m = re.match(r"^\s+expires:\s*'?([0-9-]{10})", line)
            if m and current:
                exp = m.group(1)
            m = re.match(r"^\s+reason:\s*(?:>-)?\s*(.*)$", line)
            if m and current:
                reason = m.group(1)
        if current:
            add(current, exp, reason, ".snyk")

    # .osv-scanner.toml [[IgnoredVulns]]
    f = root / ".osv-scanner.toml"
    if f.exists():
        try:
            import tomllib  # novermin  (Python 3.11+; falls back below on older Pythons)
            data = tomllib.loads(f.read_text())
            for item in data.get("IgnoredVulns", []):
                add(item.get("id"), item.get("ignoreUntil"), item.get("reason"), ".osv-scanner.toml")
        except Exception:  # noqa: BLE001 - fall back to a simple parse
            for block in f.read_text().split("[[IgnoredVulns]]")[1:]:
                vid = re.search(r'id\s*=\s*"([^"]+)"', block)
                exp = re.search(r"ignoreUntil\s*=\s*([0-9-]{10})", block)
                reason = re.search(r'reason\s*=\s*"([^"]*)"', block)
                add(vid and vid.group(1), exp and exp.group(1), reason and reason.group(1), ".osv-scanner.toml")
    return ignores, warnings


# --------------------------------------------------------------------------
# severity enrichment (OSV.dev) for tools that report none
# --------------------------------------------------------------------------

def _osv_lookup(vid: str):
    import urllib.request
    try:
        with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vid}", timeout=8) as resp:
            return json.loads(resp.read().decode())
    except Exception:  # noqa: BLE001 - offline, rate limited, unknown id
        return None


def _osv_severity(data) -> str:
    if not data:
        return "unknown"
    sev = norm_sev((data.get("database_specific") or {}).get("severity"))
    if sev != "unknown":
        return sev
    for item in data.get("severity") or []:
        sev = norm_sev(item.get("score"))
        if sev != "unknown":
            return sev
    return "unknown"


def clean_title(text: str) -> str:
    lines = [ln.strip().lstrip("#").strip() for ln in (text or "").splitlines()]
    lines = [re.sub(r"^(impact|summary|details|description|overview)\b[:\s]*", "", ln, flags=re.I) for ln in lines]
    lines = [ln for ln in lines if ln]
    return lines[0] if lines else ""


def enrich_unknown(findings, enabled=True):
    """Fill missing severities/titles from OSV.dev, preferring GitHub advisory aliases."""
    if not enabled:
        return
    todo = [f for f in findings if f["severity"] == "unknown"]
    if not todo:
        return
    from concurrent.futures import ThreadPoolExecutor
    ids = set()
    for f in todo:
        ids.update([a for a in f["aliases"] if a.upper().startswith("GHSA")] + [f["id"]])
    ids = sorted(ids)
    with ThreadPoolExecutor(max_workers=8) as pool:
        data = {vid: result for vid, result in zip(ids, pool.map(_osv_lookup, ids))}  # noqa: B905 (py3.8)
    for f in todo:
        order = [a for a in f["aliases"] if a.upper().startswith("GHSA")] + [f["id"]] + f["aliases"]
        for vid in order:
            sev = _osv_severity(data.get(vid))
            if sev != "unknown":
                f["severity"] = sev
                f["note"] = (f["note"] + "; " if f["note"] else "") + f"severity from OSV ({vid})"
                break
        if not f["title"] or f["title"].startswith("#"):
            summary = next((data[v].get("summary") for v in order if data.get(v) and data[v].get("summary")), "")
            f["title"] = summary or f["title"]


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def dedupe(findings):
    """Merge the same advisory reported by several tools."""
    merged: dict[tuple, dict] = {}
    for f in findings:
        ids = {f["id"].upper()} | {a.upper() for a in f["aliases"]}
        key = None
        for k, existing in merged.items():
            if existing["package"] == f["package"] and ids & ({existing["id"].upper()} | {a.upper() for a in existing["aliases"]}):
                key = k
                break
        if key is None:
            merged[(f["package"], f["id"], len(merged))] = {**f, "tools": [f["tool"]]}
        else:
            e = merged[key]
            if f["tool"] not in e["tools"]:
                e["tools"].append(f["tool"])
            e["aliases"] = sorted(set(e["aliases"]) | set(f["aliases"]) | {f["id"]} - {e["id"]})
            if SEV_RANK.get(f["severity"], -1) > SEV_RANK.get(e["severity"], -1):
                e["severity"] = f["severity"]
            for fld in ("version", "fixed", "title", "url", "affected"):
                e[fld] = e[fld] or f[fld]
    return list(merged.values())


def effective_rank(sev: str, unknown_as: str) -> int:
    return SEV_RANK.get(sev if sev != "unknown" else unknown_as, SEV_RANK["high"])


def main(argv=None):
    ap = argparse.ArgumentParser(description="dep-sentinel: dependency, lockfile and secret scan")
    ap.add_argument("--dir", default=".", help="project folder (default: current folder)")
    ap.add_argument("--gate", choices=SEVERITIES, default=os.environ.get("DEP_SENTINEL_GATE", "high"),
                    help="block at this severity or above (default: high)")
    ap.add_argument("--unknown-as", choices=SEVERITIES, default="high",
                    help="severity used for findings a tool reports without one (default: high)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    ap.add_argument("--report", help="also write the JSON report to this file")
    ap.add_argument("--quiet", action="store_true", help="only print when something needs attention")
    ap.add_argument("--no-secrets", action="store_true")
    ap.add_argument("--no-lockfile", action="store_true")
    ap.add_argument("--no-osv", action="store_true", help="skip the OSV-Scanner cross-check")
    ap.add_argument("--offline", action="store_true", help="do not look up missing severities on OSV.dev")
    ap.add_argument("--secrets-range", action="append", default=[],
                    help="git revision range to scan for secrets (repeatable); default: all tracked files")
    ap.add_argument("--version", action="version", version=f"dep-sentinel {VERSION}")
    args = ap.parse_args(argv)

    root = Path(args.dir).resolve()
    found = discover(root)

    def rel(p: Path) -> str:
        return os.path.relpath(p, root)

    findings, statuses = [], []
    scanners = {"npm": scan_npm, "bun": scan_bun, "pnpm": scan_pnpm, "yarn": scan_yarn}
    for folder, (pm, lock) in node_projects(found).items():
        r, s = scanners[pm](folder, rel(lock))
        findings += r
        statuses.append(s)
    reqs = [p for p in found.get("requirements.txt", []) if p.stat().st_size > 0]
    for req in reqs:
        r, s = scan_pip(req, rel(req))
        findings += r
        statuses.append(s)
    for key, fn in (("Cargo.lock", scan_cargo), ("go.mod", scan_go), ("composer.lock", scan_composer),
                    ("Gemfile.lock", scan_bundler), ("dotnet-project", scan_dotnet)):
        for path in found.get(key, []):
            r, s = fn(path, rel(path))
            findings += r
            statuses.append(s)
    osv_ran = False
    if not args.no_osv:
        r, s = scan_osv(root)
        findings += r
        statuses.append(s)
        osv_ran = s["state"] == "ran"

    # Ecosystems with a lockfile that no scanner could read.
    uncovered = []
    for key in ("poetry.lock", "Pipfile.lock", "uv.lock", "pom.xml", "build.gradle", "build.gradle.kts", "packages.lock.json"):
        for p in found.get(key, []):
            if not osv_ran:
                uncovered.append(f"{rel(p)} (install OSV-Scanner to scan this ecosystem)")
    for s in statuses:
        if s["state"] != "ran" and s["tool"] != "osv-scanner" and not osv_ran:
            uncovered.append(f"{s['target']} ({s['tool']}: {s['detail'] or s['state']})")

    findings = dedupe(findings)
    enrich_unknown(findings, enabled=not args.offline)
    ignores, ignore_warnings = load_ignores(root)
    active, ignored = [], []
    for f in findings:
        ids = {f["id"].upper()} | {a.upper() for a in f["aliases"]} | {f"{f['package']}@{f['version']}".upper()}
        hit = next((ignores[i] for i in ids if i in ignores), None)
        (ignored if hit else active).append({**f, "ignore": hit} if hit else f)

    lockfiles = [] if args.no_lockfile else check_lockfiles(found, root)
    secrets, secret_tool = ([], "disabled") if args.no_secrets else scan_secrets(root, args.secrets_range)

    gate = SEV_RANK[args.gate]
    blocking = [f for f in active if effective_rank(f["severity"], args.unknown_as) >= gate]
    out_of_sync = [lf for lf in lockfiles if lf["in_sync"] is False]
    counts = {s: 0 for s in SEVERITIES + ["unknown"]}
    for f in active:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    exit_code = 2 if (blocking or secrets or out_of_sync) else (1 if (active or uncovered) else 0)
    report = {
        "tool": "dep-sentinel", "version": VERSION, "root": str(root), "gate": args.gate,
        "exit_code": exit_code, "summary": {**counts, "blocking": len(blocking), "secrets": len(secrets),
                                            "lockfiles_out_of_sync": len(out_of_sync), "ignored": len(ignored)},
        "findings": sorted(active, key=lambda f: (-effective_rank(f["severity"], args.unknown_as), f["package"] or "")),
        "ignored": ignored, "ignore_warnings": ignore_warnings, "scanners": statuses, "not_scanned": uncovered,
        "lockfiles": lockfiles, "secrets": secrets, "secret_scanner": secret_tool,
    }
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report, args.quiet)
    return exit_code


def print_report(r, quiet):
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    paint = (lambda c, s: f"\033[{c}m{s}\033[0m") if color else (lambda c, s: s)
    sev_color = {"critical": "1;31", "high": "31", "moderate": "33", "low": "36", "unknown": "35"}
    s = r["summary"]
    if quiet and r["exit_code"] == 0:
        return
    print(paint("1", f"dep-sentinel {r['version']}") + f"  ·  {r['root']}  ·  gate: {r['gate']}")
    ran = [f"{x['tool']} ({x['target']})" for x in r["scanners"] if x["state"] == "ran"]
    print(f"  scanners: {', '.join(ran) or 'none'}  ·  secrets: {r['secret_scanner']}")
    for x in r["scanners"]:
        if x["state"] != "ran":
            print(paint("2", f"  {x['state']:7} {x['tool']} ({x['target']}): {x['detail']}"))
    if r["findings"]:
        print()
        width = max(len(f"{f['package']}@{f['version']}") for f in r["findings"][:40])
        for f in r["findings"][:40]:
            pkg = f"{f['package']}@{f['version']}" if f["version"] else f["package"]
            fix = f"  → fix: {f['fixed']}" if f["fixed"] else (f"  (affected: {f['affected']})" if f["affected"] else "")
            label = paint(sev_color.get(f["severity"], "0"), f"{f['severity'].upper():9}")
            print(f"  {label} {pkg:{width}}  {f['id']}  {f['title'][:70]}{fix}")
        if len(r["findings"]) > 40:
            print(f"  … and {len(r['findings']) - 40} more (use --json for the full list)")
    for lf in r["lockfiles"]:
        if lf["in_sync"] is False:
            print(paint("31", f"\n  LOCKFILE OUT OF SYNC  {lf['lockfile']}: {lf['detail']}"))
    for sec in r["secrets"][:20]:
        where = f"{sec['file']}:{sec['line']}" if sec["line"] else sec["file"]
        print(paint("1;31", f"  SECRET  {sec['type']}  {where}  {sec['match']}"))
    for w in r["ignore_warnings"]:
        print(paint("33", f"  ignore expired: {w}"))
    if r["not_scanned"]:
        print(paint("33", "\n  NOT SCANNED (treat as unknown, not as safe):"))
        for u in r["not_scanned"]:
            print(paint("33", f"    - {u}"))
    print()
    totals = ", ".join(f"{s[k]} {k}" for k in ("critical", "high", "moderate", "low", "unknown") if s[k])
    verdict = {0: paint("32", "PASS: no known issues"),
               1: paint("33", "WARN: issues below the gate"),
               2: paint("1;31", f"BLOCK: {s['blocking']} at/above '{r['gate']}', {s['secrets']} secret(s), "
                                  f"{s['lockfiles_out_of_sync']} lockfile(s) out of sync")}[r["exit_code"]]
    print(f"  {verdict}" + (f"  ·  {totals}" if totals else "") + (f"  ·  {s['ignored']} ignored" if s["ignored"] else ""))


if __name__ == "__main__":
    sys.exit(main())
