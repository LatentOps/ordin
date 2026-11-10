"""Validate release identities and produce bounded, inspectable integrity metadata."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import tarfile
import zipfile
from datetime import datetime
from email.parser import BytesParser
from pathlib import Path
from typing import Any, NoReturn

import importlib.util


def _bundle_helper():
    spec = importlib.util.spec_from_file_location(
        "_ordin_release_bundle", Path(__file__).with_name("release_bundle.py")
    )
    if spec is None or spec.loader is None:
        raise ValueError("exact release bundle helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create_bundle_metadata(dist: Path, *, source_root: Path, revision: str, tag: str) -> dict:
    return _bundle_helper().create_bundle_metadata(
        dist, source_root=source_root, revision=revision, tag=tag
    )


def verify_bundle(
    dist: Path, *, source_root: Path, revision: str, tag: str | None = None, tree: str | None = None
) -> dict:
    return _bundle_helper().verify_bundle(
        dist, source_root=source_root, revision=revision, tag=tag, tree=tree
    )


def _legacy_version(version: str) -> bool:
    # The historical core-only format is not an escape hatch for current releases.
    return re.fullmatch(r"0\.[0-3]\.[0-9]+", version) is not None


RELEASE_WORKFLOW_CHECKS = {
    "tests.yml": {
        "Quality",
        "Safety benchmark",
        "Build and install package",
        "Linux Debian 12",
        "Linux Fedora 42",
        "macOS 15 Python 3.13",
        "Hermes v0.21.7 hook contract",
        *(f"Python {version}" for version in ("3.10", "3.11", "3.12", "3.13")),
    },
    "security.yml": {"CodeQL Python", "Workflow security"},
    "coordinator.yml": {"PostgreSQL multi-host authority"},
    "swarm-frameworks.yml": {
        *(
            f"Installed adapter wheel ({framework})"
            for framework in ("base", "langgraph", "autogen")
        ),
        "CrewAI security quarantine",
    },
    "swarm-corpus.yml": {"Installed corpus and owned kernel evidence"},
    "swarm-assurance.yml": {
        *(
            f"Installed swarm release evidence ({platform})"
            for platform in ("ubuntu-24.04", "windows-latest")
        ),
        *(f"Protected execution Python {version}" for version in ("3.10", "3.13")),
    },
    "assurance.yml": {
        *(f"Vetted Linux kernel broker Python {version}" for version in ("3.10", "3.13")),
        *(
            f"Offline Assurance {platform} Python {version}"
            for platform in ("ubuntu-latest", "windows-latest")
            for version in ("3.10", "3.11", "3.12", "3.13")
        ),
        *(
            f"Offline optional {package} Python {version}"
            for package in ("decision_models", "security")
            for version in ("3.10", "3.13")
        ),
        *(
            f"Finite solver {platform} Python {version}"
            for platform in ("ubuntu-latest", "windows-latest")
            for version in ("3.10", "3.13")
        ),
    },
    "runtime-extension.yml": {"Native request authority"},
    "release.yml": {"Build release artifacts", "Attest tested release artifacts"},
}
RELEASE_CHECKS = set().union(*RELEASE_WORKFLOW_CHECKS.values())
MANUAL_RELEASE_WORKFLOWS = {"release.yml", "assurance.yml", "runtime-extension.yml"}
TAG_RELEASE_CHECKS = RELEASE_WORKFLOW_CHECKS["release.yml"] | {"Publish GitHub Release"}


def _github_pages(repository: str, endpoint: str) -> list[Any]:
    return json.loads(
        subprocess.check_output(
            ["gh", "api", "--paginate", "--slurp", f"repos/{repository}/{endpoint}"], text=True
        )
    )


def _main_run(run: dict[str, Any], repository: str, revision: str) -> bool:
    filename = run.get("path", "").removeprefix(".github/workflows/")
    events = (
        {"workflow_dispatch"}
        if filename in MANUAL_RELEASE_WORKFLOWS
        else {"push", "workflow_dispatch", "schedule"}
    )
    return (
        run.get("repository", {}).get("full_name") == repository
        and run.get("head_repository", {}).get("full_name") == repository
        and run.get("head_sha") == revision
        and run.get("head_branch") == "main"
        and run.get("event") in events
        and run.get("path") == f".github/workflows/{filename}"
        and filename in RELEASE_WORKFLOW_CHECKS
    )


def verify_release_checks(repository: str, revision: str, *, tag: str | None = None) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(
        r"[a-f0-9]{40}", revision
    ):
        raise ValueError("invalid release repository/revision")

    def reject(detail: str) -> NoReturn:
        raise ValueError(
            f"all maintained CI checks must pass on the exact release commit: {detail}"
        )

    def execution_start(run: dict[str, Any]) -> datetime:
        if any(
            type(run.get(field)) is not int or run[field] < 1
            for field in ("id", "check_suite_id", "run_attempt")
        ):
            reject("main workflow attempt is missing or invalid")
        attempts = _github_pages(
            repository, f"actions/runs/{run['id']}/attempts/{run['run_attempt']}"
        )
        if len(attempts) != 1 or not isinstance(attempts[0], dict):
            reject("main workflow attempt response is ambiguous")
        attempt = attempts[0]
        if not _main_run(attempt, repository, revision) or any(
            field not in run or attempt.get(field) != run[field]
            for field in (
                "id",
                "run_attempt",
                "check_suite_id",
                "path",
                "head_sha",
                "head_branch",
                "event",
                "status",
                "conclusion",
                "run_started_at",
            )
        ):
            reject("main workflow attempt identity changed or does not match")
        if any(
            not isinstance(snapshot.get(field), str)
            or re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", snapshot[field]
            )
            is None
            for snapshot in (run, attempt)
            for field in ("run_started_at", "updated_at")
        ):
            reject("main workflow execution timestamp is missing or invalid")
        try:
            started = datetime.strptime(attempt["run_started_at"], "%Y-%m-%dT%H:%M:%SZ")
            updated = datetime.strptime(attempt["updated_at"], "%Y-%m-%dT%H:%M:%SZ")
            listed_started = datetime.strptime(run["run_started_at"], "%Y-%m-%dT%H:%M:%SZ")
            listed_updated = datetime.strptime(run["updated_at"], "%Y-%m-%dT%H:%M:%SZ")
        except (KeyError, TypeError, ValueError):
            reject("main workflow execution timestamp is missing or invalid")
        # Mutable update times describe each endpoint's metadata, not execution identity.
        if updated < started or listed_updated < listed_started:
            reject("main workflow execution timestamps are inconsistent")
        if run["run_attempt"] > 1:
            previous = _github_pages(
                repository, f"actions/runs/{run['id']}/attempts/{run['run_attempt'] - 1}"
            )
            if (
                len(previous) != 1
                or not isinstance(previous[0], dict)
                or not _main_run(previous[0], repository, revision)
                or type(previous[0].get("run_attempt")) is not int
                or previous[0].get("run_attempt") != run["run_attempt"] - 1
                or any(
                    previous[0].get(field) != run[field]
                    for field in (
                        "id",
                        "check_suite_id",
                        "path",
                        "head_sha",
                        "head_branch",
                        "event",
                    )
                )
            ):
                reject("previous main workflow attempt identity does not match")
            try:
                previous_start = datetime.strptime(
                    previous[0]["run_started_at"], "%Y-%m-%dT%H:%M:%SZ"
                )
            except (KeyError, TypeError, ValueError):
                reject("previous main workflow attempt timestamp is missing or invalid")
            if previous_start >= started:
                reject("main workflow attempt chronology is ambiguous")
        return started

    runs = [
        run
        for page in _github_pages(repository, f"actions/runs?head_sha={revision}&per_page=100")
        for run in page["workflow_runs"]
    ]
    checks = [
        check
        for page in _github_pages(
            repository, f"commits/{revision}/check-runs?filter=all&per_page=100"
        )
        for check in page["check_runs"]
    ]
    by_check_id = {check["id"]: check for check in checks}
    by_suite = {run["check_suite_id"]: run for run in runs}
    main_runs: dict[str, dict[str, Any]] = {}
    main_starts: dict[str, datetime] = {}
    main_executions = []
    execution_starts = {}
    for run in runs:
        if _main_run(run, repository, revision):
            started = execution_start(run)
            main_executions.append(run)
            execution_starts[run["id"]] = started
            path = run["path"]
            # An older run ID can have the newest retry, even if that retry never
            # schedules a job. Completion time cannot order overlapping attempts.
            if path not in main_runs or started > main_starts[path]:
                main_starts[path] = started
                main_runs[path] = run
            elif started == main_starts[path] and run["id"] != main_runs[path]["id"]:
                if any(
                    candidate["status"] != "completed" or candidate["conclusion"] != "success"
                    for candidate in (run, main_runs[path])
                ):
                    reject("main workflow execution chronology is ambiguous")
    for filename in RELEASE_WORKFLOW_CHECKS:
        run = main_runs.get(f".github/workflows/{filename}")
        if not run or run["status"] != "completed" or run["conclusion"] != "success":
            reject(f"missing or unsuccessful main qualification: {filename}")

    current_tag = None
    if tag is not None:
        if (
            os.environ.get("GITHUB_EVENT_NAME") != "push"
            or os.environ.get("GITHUB_REF_TYPE") != "tag"
            or os.environ.get("GITHUB_REF") != f"refs/tags/{tag}"
            or os.environ.get("GITHUB_REF_NAME") != tag
        ):
            reject("invalid current tag context")
        current_tag = next(
            (run for run in runs if str(run["id"]) == os.environ.get("GITHUB_RUN_ID")), None
        )
        if not current_tag or not (
            current_tag.get("repository", {}).get("full_name") == repository
            and current_tag.get("head_repository", {}).get("full_name") == repository
            and current_tag.get("head_sha") == revision
            and current_tag.get("head_branch") == tag
            and current_tag.get("event") == "push"
            and current_tag.get("path") == ".github/workflows/release.yml"
            and str(current_tag.get("run_attempt")) == os.environ.get("GITHUB_RUN_ATTEMPT")
            and current_tag.get("status") in {"queued", "in_progress", "completed"}
            and current_tag.get("conclusion") in {None, "success"}
        ):
            reject("current tag workflow identity does not match")

    retired_checks = set()
    tag_checks = set()
    permitted_skips = set()
    for run in [*main_executions, *([current_tag] if current_tag else [])]:
        jobs = [
            job
            for page in _github_pages(
                repository, f"actions/runs/{run['id']}/jobs?filter=all&per_page=100"
            )
            for job in page["jobs"]
        ]
        effective_jobs: dict[str, tuple[dict[str, Any], int]] = {}
        verified_check_ids = set()
        for job in jobs:
            match = re.fullmatch(
                rf"https://api\.github\.com/repos/{re.escape(repository)}/check-runs/([0-9]+)",
                job.get("check_run_url", ""),
            )
            if (
                not match
                or job.get("run_id") != run["id"]
                or job.get("head_sha") != revision
                or type(job.get("run_attempt")) is not int
                or not 1 <= job["run_attempt"] <= run["run_attempt"]
            ):
                reject("job does not identify the expected source/workflow attempt")
            check_id = int(match[1])
            check = by_check_id.get(check_id, {})
            if (
                check.get("app", {}).get("slug") != "github-actions"
                or check.get("head_sha") != revision
                or check.get("check_suite", {}).get("id") != run["check_suite_id"]
                or check.get("name") != job["name"]
                or check.get("status") != job["status"]
                or check.get("conclusion") != job["conclusion"]
            ):
                reject("job/check source, app or workflow identity does not match")
            verified_check_ids.add(check_id)
            previous = effective_jobs.get(job["name"])
            if previous is None or (job["run_attempt"], check_id) > (
                previous[0]["run_attempt"],
                previous[1],
            ):
                if previous is not None:
                    retired_checks.add(previous[1])
                effective_jobs[job["name"]] = (job, check_id)
            elif check_id != previous[1]:
                retired_checks.add(check_id)
        if run is not current_tag and execution_starts[run["id"]] < main_starts[run["path"]]:
            # Only known jobs from an API-verified earlier execution are
            # superseded. Late-created check IDs do not make that execution new.
            retired_checks.update(verified_check_ids)
            continue
        names = set()
        for job, check_id in effective_jobs.values():
            names.add(job["name"])
            if run is current_tag:
                if job["name"] not in TAG_RELEASE_CHECKS:
                    reject("unexpected job in the current tag workflow")
                if job["run_attempt"] == run["run_attempt"]:
                    tag_checks.add(check_id)
                    # Only this API-verified tag attempt can be in progress. An
                    # untouched job from an earlier attempt must have succeeded.
                    # Neither supplies independent main release qualification.
                    if job["status"] in {"queued", "in_progress"}:
                        continue
            elif (
                (run["path"], job["name"])
                in {
                    (".github/workflows/security.yml", "Dependency review"),
                    (".github/workflows/release.yml", "Publish GitHub Release"),
                }
                and job["status"] == "completed"
                and job["conclusion"] == "skipped"
            ):
                permitted_skips.add(check_id)
                continue
            if job["status"] != "completed" or job["conclusion"] != "success":
                reject(f"unsuccessful job: {job['name']}")
        if (
            run is not current_tag
            and not RELEASE_WORKFLOW_CHECKS[run["path"].removeprefix(".github/workflows/")] <= names
        ):
            reject(f"missing maintained jobs: {run['path']}")

    latest = {}
    for check in checks:
        if check.get("head_sha") != revision or check["id"] in retired_checks:
            continue
        run = by_suite.get(check.get("check_suite", {}).get("id"))
        if run and _main_run(run, repository, revision):
            # Check IDs also order reruns of an older run ID. Do not discard an
            # entire older suite: its new retry may fail after a newer run passed.
            scope = (run["path"], "main")
        else:
            scope = (
                (run.get("path"), run.get("head_branch"), run.get("event"))
                if run
                else ("external",)
            )
        key = (check.get("app", {}).get("slug"), check["name"], scope)
        if key not in latest or check["id"] > latest[key]["id"]:
            latest[key] = check
    for check in latest.values():
        if check["id"] in permitted_skips:
            continue
        if check["id"] in tag_checks and check["status"] in {"queued", "in_progress"}:
            continue
        if check["status"] != "completed" or check["conclusion"] != "success":
            reject(f"unsuccessful additional check: {check['name']}")

    statuses = {}
    for page in _github_pages(repository, f"commits/{revision}/statuses?per_page=100"):
        for status in page:
            context = status["context"]
            if context not in statuses or status["id"] > statuses[context]["id"]:
                statuses[context] = status
    if any(status["state"] != "success" for status in statuses.values()):
        reject("unsuccessful commit status")

    analyses = [
        analysis
        for page in _github_pages(
            repository, "code-scanning/analyses?ref=refs/heads/main&tool_name=CodeQL&per_page=100"
        )
        for analysis in page
        if (
            analysis.get("commit_sha") == revision
            and analysis.get("ref") == "refs/heads/main"
            and analysis.get("analysis_key") == ".github/workflows/security.yml:codeql"
            and analysis.get("category") == "/language:python"
            and analysis.get("tool", {}).get("name") == "CodeQL"
        )
    ]
    analysis = max(analyses, key=lambda item: item["id"], default=None)
    if not analysis or analysis.get("error") or analysis.get("warning"):
        reject("missing or unsuccessful processed main CodeQL analysis")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _runtime_version(source: bytes) -> str:
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, str):
                return value
    raise ValueError("artifact runtime version is missing")


def validate_distributions(dist: Path, version: str) -> list[Path]:
    wheel = dist / f"ordin-{version}-py3-none-any.whl"
    sdist = dist / f"ordin-{version}.tar.gz"
    if set(dist.glob("*.whl")) != {wheel} or set(dist.glob("*.tar.gz")) != {sdist}:
        raise ValueError("release must contain exactly the expected wheel and source distribution")
    with zipfile.ZipFile(wheel) as archive:
        metadata = archive.read(f"ordin-{version}.dist-info/METADATA")
        runtime = archive.read("ordin/__init__.py")
        parsed = BytesParser().parsebytes(metadata)
        if (
            parsed["Name"] != "ordin"
            or parsed["Version"] != version
            or _runtime_version(runtime) != version
        ):
            raise ValueError("wheel metadata/runtime version mismatch")
    with tarfile.open(sdist, "r:gz") as archive:

        def member(name: str) -> bytes:
            info = archive.getmember(f"ordin-{version}/{name}")
            if not info.isfile() or info.size > 1024 * 1024:
                raise ValueError("invalid source distribution metadata")
            handle = archive.extractfile(info)
            if handle is None:
                raise ValueError("missing source distribution metadata")
            with handle:
                return handle.read(1024 * 1024 + 1)

        parsed = BytesParser().parsebytes(member("PKG-INFO"))
        if (
            parsed["Name"] != "ordin"
            or parsed["Version"] != version
            or _runtime_version(member("ordin/__init__.py")) != version
        ):
            raise ValueError("source distribution metadata/runtime version mismatch")
    return [wheel, sdist]


def create_metadata(dist: Path, *, version: str, revision: str, tag: str) -> None:
    if not _legacy_version(version):
        identity = create_bundle_metadata(
            dist, source_root=Path(__file__).resolve().parents[1], revision=revision, tag=tag
        )
        if identity["version"] != version:
            raise ValueError("bundle version differs from the trusted expected version")
        return
    if re.fullmatch(r"[a-f0-9]{40}", revision) is None:
        raise ValueError("release revision must be a full commit SHA")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:\.dev[0-9]+)?", version):
        raise ValueError("invalid release version")
    assets = validate_distributions(dist, version)
    components = []
    for installed in sorted(
        importlib.metadata.distributions(), key=lambda item: item.metadata.get("Name", "").lower()
    ):
        name = installed.metadata.get("Name", "")
        if name:
            components.append(
                {
                    "type": "library",
                    "name": name,
                    "version": installed.version,
                    "scope": "excluded",
                    "properties": [
                        {
                            "name": "ordin:role",
                            "value": "build-environment; not a claim of bundled runtime dependency",
                        }
                    ],
                }
            )
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "name": "ordin",
                "version": version,
                "purl": f"pkg:pypi/ordin@{version}",
            },
            "properties": [
                {"name": "ordin:source-commit", "value": revision},
                {
                    "name": "ordin:scope",
                    "value": "core artifact and observed build environment; optional extras are not installed",
                },
            ],
        },
        "components": components,
    }
    identity = {
        "schema_version": "ordin.release.v1",
        "version": version,
        "revision": revision,
        "tag": tag,
        "artifacts": {asset.name: sha256(asset) for asset in assets},
    }
    for name, payload in [("sbom.cdx.json", sbom), ("release.json", identity)]:
        with (dist / name).open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    paths = sorted([*assets, dist / "sbom.cdx.json", dist / "release.json"])
    with (dist / "SHA256SUMS").open("x", encoding="ascii") as handle:
        handle.write("".join(f"{sha256(path)}  {path.name}\n" for path in paths))


def verify_metadata(dist: Path, *, version: str, revision: str, tag: str) -> dict[str, Any]:
    if not _legacy_version(version):
        identity = verify_bundle(
            dist, source_root=Path(__file__).resolve().parents[1], revision=revision, tag=tag
        )
        if identity["version"] != version:
            raise ValueError("bundle version differs from the trusted expected version")
        return identity
    expected = {
        f"ordin-{version}-py3-none-any.whl",
        f"ordin-{version}.tar.gz",
        "sbom.cdx.json",
        "release.json",
    }
    lines = (dist / "SHA256SUMS").read_text(encoding="ascii").splitlines()
    seen = set()
    for line in lines:
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.-]+)", line)
        if match is None or match[2] not in expected or match[2] in seen:
            raise ValueError("invalid or duplicate checksum manifest entry")
        seen.add(match[2])
        path = dist / match[2]
        if path.is_symlink() or sha256(path) != match[1]:
            raise ValueError("release artifact checksum mismatch")
    if seen != expected:
        raise ValueError("release checksum manifest is incomplete")
    if (
        {path.name for path in dist.iterdir()}
        - expected
        - {"SHA256SUMS", "provenance.sigstore.json"}
    ):
        raise ValueError("unexpected release assets")
    identity = json.loads((dist / "release.json").read_text())
    if identity.get("schema_version") != "ordin.release.v1" or any(
        identity.get(key) != value
        for key, value in [("version", version), ("revision", revision), ("tag", tag)]
    ):
        raise ValueError("release/source/tag identity mismatch")
    assets = validate_distributions(dist, version)
    if identity.get("artifacts") != {asset.name: sha256(asset) for asset in assets}:
        raise ValueError("release identity artifact digests mismatch")
    return identity


def main() -> None:
    import tomllib

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["create", "verify"])
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--revision", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--publish", action="store_true")
    parser.add_argument(
        "--bundle", action="store_true", help="Require the complete five-project v2 bundle"
    )
    args = parser.parse_args()
    version = tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"]
    if _runtime_version(Path("ordin/__init__.py").read_bytes()) != version:
        raise ValueError("source package/runtime version mismatch")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if actual != args.revision:
        raise ValueError("checked-out source differs from requested release revision")
    if subprocess.check_output(["git", "status", "--porcelain"], text=True).strip():
        raise ValueError("release integrity requires a clean source checkout")
    if args.publish:
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or args.tag != f"v{version}":
            raise ValueError("published tags require exactly vX.Y.Z matching the package")
        subprocess.run(["git", "merge-base", "--is-ancestor", actual, "origin/main"], check=True)
        refs = subprocess.check_output(
            [
                "git",
                "ls-remote",
                "--exit-code",
                "origin",
                f"refs/tags/{args.tag}",
                f"refs/tags/{args.tag}^{{}}",
            ],
            text=True,
        ).splitlines()
        if not refs or refs[-1].split()[0] != actual:
            raise ValueError("remote release tag no longer identifies the tested commit")
        if (
            os.environ.get("GITHUB_EVENT_NAME") != "push"
            or os.environ.get("GITHUB_REF_TYPE") != "tag"
        ):
            raise ValueError("publishing requires a tag push event")
        verify_release_checks(os.environ["GITHUB_REPOSITORY"], actual, tag=args.tag)
    if args.mode == "create":
        if args.bundle or not _legacy_version(version):
            create_bundle_metadata(args.dist, source_root=Path.cwd(), revision=actual, tag=args.tag)
        else:
            create_metadata(args.dist, version=version, revision=actual, tag=args.tag)
    print(
        json.dumps(
            verify_bundle(args.dist, source_root=Path.cwd(), revision=actual, tag=args.tag)
            if args.bundle
            else verify_metadata(args.dist, version=version, revision=actual, tag=args.tag),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
