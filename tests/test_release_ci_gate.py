"""Publication must qualify the actual source, not merely recognize job names."""

from copy import deepcopy
import json

import pytest

from scripts.release_integrity import RELEASE_CHECKS, RELEASE_WORKFLOW_CHECKS, verify_release_checks


REPOSITORY = "LatentOps/ordin"
REVISION = "a" * 40
TAG = "v1.2.3"
LEGACY_CHECKS = {
    "Quality",
    "Safety benchmark",
    "Build and install package",
    "Linux Debian 12",
    "Linux Fedora 42",
    "macOS 15 Python 3.13",
    "Python 3.10",
    "Python 3.11",
    "Python 3.12",
    "Python 3.13",
    "CodeQL Python",
    "Workflow security",
}
NEW_LANES = [
    "Installed adapter wheel (langgraph)",
    "CrewAI security quarantine",
    "PostgreSQL multi-host authority",
    "Installed corpus and owned kernel evidence",
    "Installed swarm release evidence (windows-latest)",
    "Offline Assurance ubuntu-latest Python 3.12",
    "Offline optional decision_models Python 3.13",
    "Finite solver windows-latest Python 3.10",
    "Vetted Linux kernel broker Python 3.13",
    "Native request authority",
    "Build release artifacts",
    "Attest tested release artifacts",
]


class ReleaseAPI:
    def __init__(self, monkeypatch):
        self.runs = []
        self.checks = []
        self.jobs = {}
        self.statuses = []
        self.calls = []
        self.analyses = [
            {
                "id": 1,
                "commit_sha": REVISION,
                "ref": "refs/heads/main",
                "analysis_key": ".github/workflows/security.yml:codeql",
                "category": "/language:python",
                "tool": {"name": "CodeQL"},
                "error": "",
                "warning": "",
            }
        ]
        for filename, names in RELEASE_WORKFLOW_CHECKS.items():
            extra = (
                {"Dependency review"}
                if filename == "security.yml"
                else ({"Publish GitHub Release"} if filename == "release.yml" else set())
            )
            self.add_run(filename, names | extra)
        monkeypatch.setattr("scripts.release_integrity.subprocess.check_output", self.query)

    def add_run(self, filename, names, *, branch="main", event=None):
        run_id = 1 + max((run["id"] for run in self.runs), default=0)
        event = event or (
            "workflow_dispatch"
            if filename in {"release.yml", "assurance.yml", "runtime-extension.yml"}
            else "push"
        )
        run = {
            "id": run_id,
            "path": f".github/workflows/{filename}",
            "head_sha": REVISION,
            "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
            "head_branch": branch,
            "event": event,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "check_suite_id": run_id + 100,
        }
        self.runs.append(run)
        self.jobs[run_id] = []
        for name in sorted(names):
            self.add_job(
                run,
                name,
                skipped=branch == "main"
                and name in {"Dependency review", "Publish GitHub Release"},
            )
        return run

    def add_job(self, run, name, *, skipped=False):
        check_id = 1 + max((check["id"] for check in self.checks), default=1000)
        check = {
            "id": check_id,
            "name": name,
            "head_sha": REVISION,
            "app": {"slug": "github-actions"},
            "check_suite": {"id": run["check_suite_id"]},
            "status": "completed",
            "conclusion": "skipped" if skipped else "success",
        }
        job = {
            "id": check_id,
            "name": name,
            "head_sha": REVISION,
            "run_id": run["id"],
            "run_attempt": run["run_attempt"],
            "status": check["status"],
            "conclusion": check["conclusion"],
            "check_run_url": f"https://api.github.com/repos/{REPOSITORY}/check-runs/{check_id}",
        }
        self.checks.append(check)
        self.jobs[run["id"]].append(job)
        return job

    def job(self, name):
        return next(job for jobs in self.jobs.values() for job in jobs if job["name"] == name)

    def check(self, job):
        return next(check for check in self.checks if check["id"] == job["id"])

    def outcome(self, job, status, conclusion):
        for record in (job, self.check(job)):
            record.update(status=status, conclusion=conclusion)

    def tag_run(self, monkeypatch):
        run = self.add_run(
            "release.yml",
            {
                "Build release artifacts",
                "Attest tested release artifacts",
                "Publish GitHub Release",
            },
            branch=TAG,
            event="push",
        )
        run.update(status="in_progress", conclusion=None)
        for job in self.jobs[run["id"]]:
            self.outcome(
                job, "in_progress" if job["name"] == "Build release artifacts" else "queued", None
            )
        for key, value in {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF_TYPE": "tag",
            "GITHUB_REF": f"refs/tags/{TAG}",
            "GITHUB_REF_NAME": TAG,
            "GITHUB_RUN_ID": str(run["id"]),
            "GITHUB_RUN_ATTEMPT": "1",
        }.items():
            monkeypatch.setenv(key, value)
        return run

    def query(self, command, *, text):
        assert command[:4] == ["gh", "api", "--paginate", "--slurp"]
        assert text is True
        endpoint = command[4].removeprefix(f"repos/{REPOSITORY}/")
        self.calls.append(endpoint)
        if endpoint == f"actions/runs?head_sha={REVISION}&per_page=100":
            rows, key = self.runs, "workflow_runs"
        elif endpoint == f"commits/{REVISION}/check-runs?filter=all&per_page=100":
            rows, key = self.checks, "check_runs"
        elif endpoint == f"commits/{REVISION}/statuses?per_page=100":
            rows, key = self.statuses, None
        elif endpoint == "code-scanning/analyses?ref=refs/heads/main&tool_name=CodeQL&per_page=100":
            rows, key = self.analyses, None
        else:
            prefix, suffix = "actions/runs/", "/jobs?filter=all&per_page=100"
            assert endpoint.startswith(prefix) and endpoint.endswith(suffix), endpoint
            rows, key = self.jobs[int(endpoint[len(prefix) : -len(suffix)])], "jobs"
        # Deliberately spread the required evidence across many pages.
        pages = [rows[index : index + 3] for index in range(0, len(rows), 3)] or [[]]
        return json.dumps([{key: page} if key else page for page in pages])


@pytest.fixture
def api(monkeypatch):
    return ReleaseAPI(monkeypatch)


def test_current_main_policy_qualifies_all_paginated_evidence(api):
    assert len(RELEASE_CHECKS) == 42
    assert set(NEW_LANES) <= RELEASE_CHECKS
    verify_release_checks(REPOSITORY, REVISION)
    assert len([call for call in api.calls if "/jobs?" in call]) == 9


def test_twelve_legacy_names_are_insufficient_even_with_successful_run_summaries(api):
    for run_id, jobs in api.jobs.items():
        api.jobs[run_id] = [job for job in jobs if job["name"] in LEGACY_CHECKS]
    api.checks[:] = [check for check in api.checks if check["name"] in LEGACY_CHECKS]
    with pytest.raises(ValueError, match="missing maintained jobs"):
        verify_release_checks(REPOSITORY, REVISION)


@pytest.mark.parametrize("name", NEW_LANES)
@pytest.mark.parametrize("outcome", ["missing", "failure", "pending"])
def test_new_required_lanes_cannot_be_missing_failed_or_pending(api, name, outcome):
    job = api.job(name)
    if outcome == "missing":
        api.jobs[job["run_id"]].remove(job)
    else:
        api.outcome(
            job,
            "in_progress" if outcome == "pending" else "completed",
            None if outcome == "pending" else "failure",
        )
    with pytest.raises(ValueError, match="exact release commit"):
        verify_release_checks(REPOSITORY, REVISION)


@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", "b" * 40),
        ("app", {"slug": "foreign-app"}),
        ("check_suite", {"id": 99999}),
    ],
)
def test_foreign_check_identity_cannot_supply_a_required_job(api, field, value):
    api.check(api.job("Native request authority"))[field] = value
    with pytest.raises(ValueError, match="job/check source, app or workflow"):
        verify_release_checks(REPOSITORY, REVISION)


def test_a_required_lane_cannot_be_skipped(api):
    api.outcome(api.job("Installed adapter wheel (autogen)"), "completed", "skipped")
    with pytest.raises(ValueError, match="unsuccessful job"):
        verify_release_checks(REPOSITORY, REVISION)


def test_a_familiar_skip_name_from_a_foreign_suite_is_not_a_waiver(api):
    extra = deepcopy(api.check(api.job("Dependency review")))
    extra.update(id=5000, check_suite={"id": 8888})
    api.checks.append(extra)
    with pytest.raises(ValueError, match="additional check"):
        verify_release_checks(REPOSITORY, REVISION)


@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", "b" * 40),
        ("head_branch", "fix/elsewhere"),
        ("event", "pull_request"),
        ("path", ".github/workflows/foreign.yml"),
        ("repository", {"full_name": "elsewhere/ordin"}),
        ("head_repository", {"full_name": "elsewhere/ordin"}),
    ],
)
def test_same_named_jobs_from_a_foreign_workflow_or_source_do_not_qualify(api, field, value):
    run = next(run for run in api.runs if run["path"].endswith("runtime-extension.yml"))
    run[field] = value
    with pytest.raises(ValueError, match="main qualification"):
        verify_release_checks(REPOSITORY, REVISION)


def test_a_later_main_run_supersedes_only_its_own_workflow(api):
    original = next(run for run in api.runs if run["path"].endswith("runtime-extension.yml"))
    original.update(conclusion="failure")
    api.outcome(api.job("Native request authority"), "completed", "failure")
    api.add_run("runtime-extension.yml", {"Native request authority"})
    verify_release_checks(REPOSITORY, REVISION)
    original.update(path=".github/workflows/unrelated.yml")
    with pytest.raises(ValueError, match="additional check"):
        verify_release_checks(REPOSITORY, REVISION)


@pytest.mark.parametrize("outcome", ["failure", "pending"])
def test_retry_of_an_older_run_cannot_hide_behind_a_later_successful_run_id(api, outcome):
    original = next(run for run in api.runs if run["path"].endswith("runtime-extension.yml"))
    api.add_run("runtime-extension.yml", {"Native request authority"})
    original["run_attempt"] = 2
    if outcome == "pending":
        original.update(status="in_progress", conclusion=None)
    job = api.add_job(original, "Native request authority")
    api.outcome(
        job,
        "in_progress" if outcome == "pending" else "completed",
        None if outcome == "pending" else "failure",
    )
    with pytest.raises(ValueError, match="exact release commit"):
        verify_release_checks(REPOSITORY, REVISION)


@pytest.mark.parametrize("latest_outcome", ["success", "failure", "pending"])
def test_latest_attempt_supersedes_old_attempts_without_hiding_a_new_failure(api, latest_outcome):
    run = next(run for run in api.runs if run["path"].endswith("runtime-extension.yml"))
    api.outcome(api.job("Native request authority"), "completed", "failure")
    run["run_attempt"] = 2
    new_job = api.add_job(run, "Native request authority")
    api.outcome(
        new_job,
        "in_progress" if latest_outcome == "pending" else "completed",
        None if latest_outcome == "pending" else latest_outcome,
    )
    if latest_outcome == "success":
        verify_release_checks(REPOSITORY, REVISION)
    else:
        with pytest.raises(ValueError, match="unsuccessful job"):
            verify_release_checks(REPOSITORY, REVISION)


@pytest.mark.parametrize("status,conclusion", [("in_progress", None), ("completed", "failure")])
@pytest.mark.parametrize(
    "app,name",
    [("external-service", "New regression lane"), ("github-advanced-security", "CodeQL")],
)
def test_additional_checks_and_the_optional_pr_aggregate_cannot_hide_failures(
    api, status, conclusion, app, name
):
    extra = deepcopy(api.checks[0])
    extra.update(
        id=5000,
        name=name,
        status=status,
        conclusion=conclusion,
        app={"slug": app},
        check_suite={"id": 8888},
    )
    api.checks.append(extra)
    with pytest.raises(ValueError, match="additional check"):
        verify_release_checks(REPOSITORY, REVISION)


def test_external_check_retry_uses_the_latest_result_from_the_same_app_and_name(api):
    extra = deepcopy(api.checks[0])
    extra.update(
        id=5000,
        name="External regression lane",
        conclusion="failure",
        app={"slug": "external-service"},
        check_suite={"id": 8888},
    )
    api.checks.append(extra)
    api.checks.append({**extra, "id": 5001, "conclusion": "success", "check_suite": {"id": 8889}})
    verify_release_checks(REPOSITORY, REVISION)
    api.checks[-1]["app"] = {"slug": "different-app"}
    with pytest.raises(ValueError, match="additional check"):
        verify_release_checks(REPOSITORY, REVISION)


@pytest.mark.parametrize("state", ["pending", "failure", "error"])
def test_latest_commit_status_must_succeed_across_all_pages(api, state):
    api.statuses = [{"id": n, "context": f"context-{n}", "state": "success"} for n in range(5)]
    api.statuses += [{"id": 10, "context": "context-0", "state": state}]
    with pytest.raises(ValueError, match="commit status"):
        verify_release_checks(REPOSITORY, REVISION)
    api.statuses.append({"id": 11, "context": "context-0", "state": "success"})
    verify_release_checks(REPOSITORY, REVISION)


@pytest.mark.parametrize(
    "field,value",
    [
        ("commit_sha", "b" * 40),
        ("ref", "refs/pull/1/merge"),
        ("analysis_key", "other:codeql"),
        ("category", "/language:javascript"),
        ("tool", {"name": "Other"}),
        ("error", "analysis failed"),
        ("warning", "analysis incomplete"),
    ],
)
def test_codeql_requires_processed_exact_main_python_analysis(api, field, value):
    api.analyses[0][field] = value
    with pytest.raises(ValueError, match="processed main CodeQL"):
        verify_release_checks(REPOSITORY, REVISION)


def test_newer_failed_processed_analysis_cannot_borrow_an_older_success(api):
    api.analyses.append({**api.analyses[0], "id": 2, "error": "failed"})
    with pytest.raises(ValueError, match="processed main CodeQL"):
        verify_release_checks(REPOSITORY, REVISION)


def test_current_tag_jobs_neither_self_block_nor_supply_prior_main_acceptance(api, monkeypatch):
    tag_run = api.tag_run(monkeypatch)
    verify_release_checks(REPOSITORY, REVISION, tag=TAG)
    api.runs[:] = [
        run for run in api.runs if run is tag_run or not run["path"].endswith("release.yml")
    ]
    with pytest.raises(ValueError, match="main qualification: release.yml"):
        verify_release_checks(REPOSITORY, REVISION, tag=TAG)


@pytest.mark.parametrize(
    "field,value",
    [
        ("head_sha", "b" * 40),
        ("head_branch", "v9.9.9"),
        ("event", "workflow_dispatch"),
        ("path", ".github/workflows/unrelated.yml"),
        ("run_attempt", 2),
        ("repository", {"full_name": "elsewhere/ordin"}),
        ("head_repository", {"full_name": "elsewhere/ordin"}),
    ],
)
def test_current_tag_exemption_requires_the_api_confirmed_identity(api, monkeypatch, field, value):
    api.tag_run(monkeypatch)[field] = value
    with pytest.raises(ValueError, match="tag workflow identity"):
        verify_release_checks(REPOSITORY, REVISION, tag=TAG)


def test_current_tag_completed_failures_and_unrecognized_jobs_still_block(api, monkeypatch):
    run = api.tag_run(monkeypatch)
    job = next(job for job in api.jobs[run["id"]] if job["name"] == "Build release artifacts")
    api.outcome(job, "completed", "failure")
    with pytest.raises(ValueError, match="unsuccessful job"):
        verify_release_checks(REPOSITORY, REVISION, tag=TAG)
    api.outcome(job, "completed", "success")
    api.add_job(run, "Unknown tag check")
    with pytest.raises(ValueError, match="unexpected job"):
        verify_release_checks(REPOSITORY, REVISION, tag=TAG)


def test_a_tag_publish_skip_cannot_borrow_the_manual_release_exception(api, monkeypatch):
    run = api.tag_run(monkeypatch)
    job = next(job for job in api.jobs[run["id"]] if job["name"] == "Publish GitHub Release")
    api.outcome(job, "completed", "skipped")
    with pytest.raises(ValueError, match="unsuccessful job"):
        verify_release_checks(REPOSITORY, REVISION, tag=TAG)


def test_current_tag_check_app_identity_cannot_be_spoofed(api, monkeypatch):
    run = api.tag_run(monkeypatch)
    api.check(api.jobs[run["id"]][0])["app"] = {"slug": "foreign-app"}
    with pytest.raises(ValueError, match="job/check source, app or workflow"):
        verify_release_checks(REPOSITORY, REVISION, tag=TAG)


def test_current_tag_retry_retires_only_api_identified_prior_attempt_jobs(api, monkeypatch):
    run = api.tag_run(monkeypatch)
    for job in api.jobs[run["id"]]:
        api.outcome(job, "completed", "failure")
    run["run_attempt"] = 2
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    current = api.add_job(run, "Build release artifacts")
    api.outcome(current, "in_progress", None)
    verify_release_checks(REPOSITORY, REVISION, tag=TAG)


def test_tag_exemption_does_not_cover_another_run(api, monkeypatch):
    api.tag_run(monkeypatch)
    other = api.add_run("release.yml", {"Build release artifacts"}, branch="v0.0.1", event="push")
    api.outcome(api.jobs[other["id"]][0], "in_progress", None)
    with pytest.raises(ValueError, match="additional check"):
        verify_release_checks(REPOSITORY, REVISION, tag=TAG)
